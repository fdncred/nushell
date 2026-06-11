// ============================================================================
// uls (uu_ls-based directory listing command)
// ============================================================================
//
// This file implements the `uls` nushell command, which uses the uu_ls
// (coreutils ls) library to list directory entries. uu_ls provides
// cross-platform metadata reading (symlinks, permissions, timestamps)
// and error handling that works correctly on Windows, macOS, and Linux.
//
// Architecture overview:
//   1. Parse nushell arguments → build uu_ls Config
//   2. Expand glob patterns (or resolve literal paths)
//   3. List metadata via uu_ls (sequential or parallel/chunked)
//   4. Convert uu_ls EntryInfo entries into nushell Value::Record rows
//   5. Sort by name and return as PipelineData
//
// The parallel path divides the path list into N chunks (where N = available
// parallelism), processes each chunk in its own thread via uu_ls, then
// merges and re-sorts. This avoids the overhead of spawning one thread
// per file while still utilising multiple cores for metadata I/O.
// ============================================================================

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
// chrono: SystemTime ↔ DateTime conversions for the "modified"/"created"/"accessed" columns.
use chrono::{DateTime, Local, LocalResult, TimeZone, Utc};
// nu_engine: re-exports the nushell command prelude (Value, Record, Span, ShellError,
// etc.) plus glob_from() which routes to either nushell's built-in glob backend
// or the experimental dc_glob backend depending on the DC_GLOB feature flag.
use nu_engine::{command_prelude::*, glob_from};
// nu_glob: glob matching options (e.g. whether to recurse into hidden dirs).
use nu_glob::MatchOptions;
// nu_path: path expansion with tilde (~) support.
use nu_path::expand_path_with;
// nu_protocol: core nushell types.
// - NuGlob: a glob pattern with an "expand" flag (tilde expansion).
// - PipelineMetadata: table metadata for the output (width-priority columns).
// - Signals: shared signalling for cancellation/interrupt support.
// - shell_error: nushell's standardised error types (GenericError, IoError).
use nu_protocol::{
    NuGlob, PipelineMetadata, Signals,
    shell_error::{self, generic::GenericError, io::IoError},
};
// pathdiff: computing relative paths between two absolute paths (used by
// make_relative_to_cwd for display names).
use pathdiff::diff_paths;
// std: standard library types. Note that std::fs is *not* imported here:
// all filesystem metadata reading is done through uu_ls for correct
// cross-platform error handling.
use std::{
    path::{Path, PathBuf},
    sync::mpsc,    // multi-producer, single-consumer channels for parallel results
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
// uu_ls: the coreutils ls library. Config holds ls flags, EntryInfo wraps
// a file's path + metadata, and StreamingOutput collects results from
// list_with_output().
use uu_ls::{Config, EntryInfo, StreamingOutput};
// uucore: utility crate for all uu tools. setup_localization initialises
// Fluent message bundles so that uu_ls error messages (via translate!())
// render in the user's locale rather than as raw message IDs.
use uucore::locale::setup_localization;
// nushell internal utilities: DirBuilder and DirInfo are used by the --du
// flag to compute recursive directory sizes.
use crate::{DirBuilder, DirInfo};

// ---------------------------------------------------------------------------
// Public command struct
// ---------------------------------------------------------------------------

/// The `uls` command struct. Zero-sized: all state lives in the arguments
/// and engine state passed to `run()`.
#[derive(Clone)]
pub struct ULs;

// ---------------------------------------------------------------------------
// Internal arguments bag
// ---------------------------------------------------------------------------

/// Nushell flag values extracted from the `Call` at the start of `run()`.
/// These are passed through the call chain instead of threading the raw
/// `Call` reference, avoiding lifetime complexity.
#[derive(Clone, Copy)]
struct Args {
    /// -a / --all: show hidden files (maps to GNU ls --almost-all / -A)
    all: bool,
    /// -l / --long: show all available columns (permissions, timestamps, etc.)
    long: bool,
    /// -s / --short-names: only the file/directory name, no path prefix
    short_names: bool,
    /// -f / --full-paths: always display absolute paths
    full_paths: bool,
    /// -d / --du: compute recursive directory size ("disk usage") for dirs
    du: bool,
    /// -D / --directory: show the directory entry itself, not its contents
    directory: bool,
    /// -m / --mime-type: guess MIME type from filename extension for "file" entries
    use_mime_type: bool,
    /// -t / --threads: use multiple threads for listing (chunked parallelism)
    use_threads: bool,
    /// The span of the original `uls` call, used for error reporting
    call_span: Span,
}

// ============================================================================
// Command trait implementation
// ============================================================================

impl Command for ULs {
    /// The command name as used in nushell scripts (e.g. `uls *.rs`).
    fn name(&self) -> &str {
        "uls"
    }

    /// Short description shown in `--help` and the help system.
    fn description(&self) -> &str {
        "List the filenames, sizes, and modification times of items in a directory."
    }

    /// Search terms for the nushell `help` system's keyword lookup.
    fn search_terms(&self) -> Vec<&str> {
        vec!["dir"]
    }

    /// Declares the command signature: positional arguments, flags, input/output types.
    fn signature(&self) -> nu_protocol::Signature {
        Signature::build("uls")
            // Accepts Nothing as input (piped glob results also work via rest args)
            .input_output_types(vec![(Type::Nothing, Type::table())])
            // Rest argument: one or more glob patterns or literal paths
            .rest(
                "pattern",
                SyntaxShape::OneOf(vec![SyntaxShape::GlobPattern, SyntaxShape::String]),
                "The glob pattern to use.",
            )
            .switch("all", "Show hidden files.", Some('a'))
            .switch(
                "long",
                "Get all available columns for each entry (slower; columns are platform-dependent).",
                Some('l'),
            )
            .switch(
                "short-names",
                "Only print the file names, and not the path.",
                Some('s'),
            )
            .switch("full-paths", "Display paths as absolute paths.", Some('f'))
            .switch(
                "du",
                "Display the apparent directory size (\"disk usage\") in place of the directory metadata size.",
                Some('d'),
            )
            .switch(
                "directory",
                "List the specified directory itself instead of its contents.",
                Some('D'),
            )
            .switch(
                "mime-type",
                "Show mime-type in type column instead of 'file' (based on filenames only; files' contents are not examined).",
                Some('m'),
            )
            .switch(
                "threads",
                "Use multiple threads to list contents. Output will be non-deterministic.",
                Some('t'),
            )
            .category(Category::FileSystem)
    }

    // -----------------------------------------------------------------------
    // run() — the main command entry point
    //
    // Pipeline:
    //   1. Extract all flags → Args struct
    //   2. Initialise uu_ls localization for error messages
    //   3. Determine whether the pattern contains glob metacharacters
    //   4. Expand globs or resolve literal paths → Vec<PathBuf>
    //   5. Build uu_ls Config from the nushell Args
    //   6. Decide sequential vs parallel listing
    //   7. Convert paths to Values and return as PipelineData
    // -----------------------------------------------------------------------
    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // ---- Step 1: Extract all flags from the nushell call --------------
        let all = call.has_flag(engine_state, stack, "all")?;
        let long = call.has_flag(engine_state, stack, "long")?;
        let short_names = call.has_flag(engine_state, stack, "short-names")?;
        let full_paths = call.has_flag(engine_state, stack, "full-paths")?;
        let du = call.has_flag(engine_state, stack, "du")?;
        let directory = call.has_flag(engine_state, stack, "directory")?;
        let use_mime_type = call.has_flag(engine_state, stack, "mime-type")?;
        let call_span = call.head;
        let cwd = engine_state.cwd(Some(stack))?.into_std_path_buf();

        // ---- Step 2: Initialise localization for uu_ls error messages -----
        //
        // uu_ls emits error messages via uucore's translate!() macro, which
        // requires Fluent bundles to be loaded. This call is a no-op after
        // the first time (guarded by LazyLock internally), so it's safe to
        // call on every invocation.
        let _ = setup_localization("ls");

        let use_threads = call.has_flag(engine_state, stack, "threads")?;

        // Bundle all flags into the internal Args struct for easy passing.
        let args = Args {
            all,
            long,
            short_names,
            full_paths,
            du,
            directory,
            use_mime_type,
            use_threads,
            call_span,
        };

        // ---- Step 3: Parse rest arguments (glob patterns or paths) --------

        // Rest args are Spanned<NuGlob> — NuGlob wraps a string with an
        // "expand" flag (whether to expand ~ and environment variables).
        let patterns = call.rest::<Spanned<NuGlob>>(engine_state, stack, 0)?;
        let patterns_opt = if !call.has_positional_args(stack, 0) {
            None // bare `uls` with no arguments
        } else {
            Some(patterns)
        };

        // ---- Step 4: Determine if any pattern has glob metacharacters -----
        //
        // When a pattern has no glob metacharacters (*, ?, [, ]), we can
        // resolve it directly as a filesystem path without going through
        // the glob engine. This avoids issues on Windows where backslashes
        // in paths can be misinterpreted as glob escape sequences.
        //
        // is_expand() is true for NuGlob::Expand variants (~ expansion).
        // has_glob_metachars() checks for *, ?, [, ] in the string.
        let has_glob_meta = patterns_opt.as_ref().is_some_and(|pats| {
            pats.iter()
                .any(|p| p.item.is_expand() && has_glob_metachars(p.item.as_ref()))
        });

        // ---- Step 5: Expand patterns to concrete paths -------------------
        let paths = if has_glob_meta {
            // Use glob_from() which routes to nushell's glob backend or
            // dc_glob depending on the DC_GLOB feature flag.
            expand_glob_patterns(patterns_opt, &args, &cwd, engine_state.signals())?
        } else {
            // Resolve as literal filesystem paths (skips glob entirely).
            resolve_literal_patterns(patterns_opt, &args, &cwd)?
        };

        // Short-circuit: empty result → return empty pipeline data.
        if paths.is_empty() {
            return Ok(PipelineData::Empty);
        }

        // ---- Step 6: Build uu_ls Config from nushell Args ----------------
        //
        // When has_glob_meta is true, we force the -d flag so that uu_ls
        // shows each matched path as an entry without descending into
        // directories. This is correct because glob already resolved which
        // paths exist — we don't want uu_ls to re-read directory contents.
        let config = build_uu_config(&args, has_glob_meta)?;

        // ---- Step 7: List entries (sequential or parallel) ---------------
        //
        // Parallel is only beneficial when there are many paths (> 1) and
        // the --threads flag is given. The parallel path divides paths into
        // N chunks (N = available parallelism) and processes each in its
        // own thread via uu_ls, then merges results.
        let values = if paths.is_empty() {
            vec![]
        } else if args.use_threads && paths.len() > 1 {
            list_parallel(paths, &config, &args, &cwd, has_glob_meta)?
        } else {
            list_sequential(paths, &config, &args, &cwd, has_glob_meta)?
        };

        // ---- Step 8: Wrap results in PipelineData with metadata ----------
        //
        // into_pipeline_data_with_metadata attaches table-layout hints
        // (width-priority columns) so the table renderer knows which
        // columns to prioritise when terminal width is limited.
        Ok(values.into_pipeline_data_with_metadata(
            call_span,
            engine_state.signals().clone(),
            ls_pipeline_metadata(call_span, long),
        ))
    }

    // -----------------------------------------------------------------------
    // examples() — documentation examples shown in --help and `help uls`
    // -----------------------------------------------------------------------
    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "List visible files in the current directory.",
                example: "uls",
                result: None,
            },
            Example {
                description: "List visible files in a subdirectory.",
                example: "uls subdir",
                result: None,
            },
            Example {
                description: "List visible files with full path in the parent directory.",
                example: "uls -f ..",
                result: None,
            },
            Example {
                description: "List Rust files.",
                example: "uls *.rs",
                result: None,
            },
            Example {
                description: "List files and directories whose name do not contain 'bar'.",
                example: "uls | where name !~ bar",
                result: None,
            },
            Example {
                description: "List the full path of all dirs in your home directory.",
                example: "uls -a ~ | where type == dir",
                result: None,
            },
            Example {
                description: "List only the names (not paths) of all dirs in your home directory which have not been modified in 7 days.",
                example: "uls -as ~ | where type == dir and modified < ((date now) - 7day)",
                result: None,
            },
            Example {
                description: "Recursively list all files and subdirectories under the current directory using a glob pattern.",
                example: "uls -a **/*",
                result: None,
            },
            Example {
                description: "Recursively list *.rs and *.toml files using the glob command.",
                example: "uls ...(glob **/*.{rs,toml})",
                result: None,
            },
            Example {
                description: "List given paths and show directories themselves.",
                example: "['/path/to/directory' '/path/to/file'] | each {|| uls -D $in } | flatten",
                result: None,
            },
        ]
    }
}

// ============================================================================
// Glob expansion
// ============================================================================

/// Expands one or more nushell glob patterns into concrete filesystem paths.
///
/// This function is the main entry point for pattern matching. It:
/// 1. Handles single vs multiple patterns (multiple patterns are processed
///    recursively, one at a time, and their results are merged).
/// 2. Rejects empty-string patterns early with a clear error.
/// 3. Checks for empty directories before expanding (for non-`--directory`
///    invocations, an empty directory returns no results).
/// 4. Delegates to `glob_from()` which selects the active glob backend
///    (nushell's built-in or dc_glob based on the feature flag).
/// 5. Returns an error if no paths matched, rather than silently returning
///    an empty list (matching nushell's existing `ls` behaviour).
fn expand_glob_patterns(
    patterns: Option<Vec<Spanned<NuGlob>>>,
    args: &Args,
    cwd: &std::path::Path,
    signals: &Signals,
) -> Result<Vec<PathBuf>, ShellError> {
    let span = args.call_span;

    // ---- Single pattern path ---------------------------------------------
    // Separate single-pattern from multi-pattern to avoid unnecessary
    // Vec allocations in the common case (one glob pattern).
    let pattern_arg = match patterns {
        Some(mut pats) if pats.len() == 1 => {
            let pat = pats.remove(0);
            // Reject empty-string patterns early — they can never match a
            // real filesystem entry and would produce confusing errors
            // downstream.
            if pat.item.as_ref().is_empty() {
                return Err(ShellError::Io(IoError::new_with_additional_context(
                    shell_error::io::ErrorKind::from_std(std::io::ErrorKind::NotFound),
                    pat.span,
                    PathBuf::from(pat.item.to_string()),
                    "empty string('') directory or file does not exist",
                )));
            }
            // Strip ANSI escape sequences that may have been introduced by
            // the parser (e.g. syntax highlighting). The glob engine does
            // not understand escape sequences.
            Some(pat.map(NuGlob::strip_ansi_string_unlikely))
        }
        // ---- Multiple patterns path --------------------------------------
        // Recurse for each pattern individually, then merge results.
        // This matches the existing nushell `ls` behaviour where multiple
        // rest args are processed independently and their results flattened.
        Some(pats) => {
            let mut paths = Vec::new();
            for pat in pats {
                let single = expand_glob_patterns(Some(vec![pat]), args, cwd, signals)?;
                paths.extend(single);
            }
            return Ok(paths);
        }
        None => None,
    };

    // ---- Empty-directory pre-check ---------------------------------------
    // Before running the expensive glob expansion, check whether the target
    // is an empty directory. If so, return an empty result immediately.
    // This is an optimisation that also preserves nushell's existing
    // behaviour where `ls empty_dir` returns nothing (instead of an error).
    let p_tag: Span = pattern_arg.as_ref().map(|p| p.span).unwrap_or(span);
    let pattern = match pattern_arg {
        Some(pat) => {
            let tmp_expanded = expand_path_with(pat.item.as_ref(), cwd, pat.item.is_expand());
            if !args.directory
                && tmp_expanded.is_dir()
                && tmp_expanded
                    .read_dir()
                    .map_err(|err| ShellError::Io(IoError::new(err, p_tag, tmp_expanded.clone())))?
                    .next()
                    .is_none()
            {
                return Ok(Vec::new());
            }
            pat.item
        }
        None => {
            if !args.directory
                && cwd
                    .read_dir()
                    .map_err(|err| ShellError::Io(IoError::new(err, span, cwd.to_path_buf())))?
                    .next()
                    .is_none()
            {
                return Ok(Vec::new());
            } else {
                NuGlob::Expand(".".to_string())
            }
        }
    };

    // ---- Execute glob expansion ------------------------------------------
    let path = pattern.into_spanned(p_tag);

    // When --all is not set, suppress matching inside hidden directories
    // (those starting with `.`). This is only relevant for recursive
    // patterns like `**/*`.
    let glob_options = if args.all {
        None
    } else {
        Some(MatchOptions {
            recursive_match_hidden_dir: false,
            ..Default::default()
        })
    };

    // glob_from() returns (prefix, iterator). The prefix is the base path
    // that was stripped before matching; we don't need it here because
    // glob_from already rebuilds full paths in the iterator.
    let (_prefix, glob_paths) = glob_from(&path, cwd, span, glob_options, signals.clone())?;

    // Collect only successful matches (filtering out permission-denied etc.)
    let paths: Vec<PathBuf> = glob_paths.filter_map(|r| r.ok()).collect();

    // If nothing matched, return an error rather than silently succeeding
    // with an empty list. This matches nushell's `ls` behaviour.
    if paths.is_empty() {
        return Err(ShellError::Generic(
            GenericError::new(
                format!("No matches found for {:?}", path.item),
                "Pattern, file or folder not found",
                p_tag,
            )
            .with_help("no matches found"),
        ));
    }

    Ok(paths)
}

// ============================================================================
// Literal pattern resolution (non-glob paths)
// ============================================================================

/// Resolves literal (non-glob) patterns into concrete filesystem paths.
///
/// This function **does not** use the glob engine. Instead, it:
/// - `None` (bare `uls` with no arguments): resolves to `cwd` itself.
/// - `.`: resolves to `cwd`.
/// - Any other path: expanded via `expand_path_with` (tilde/var expansion).
///
/// Why bypass glob for literal paths?
/// -----------------------------------
/// On Windows, filesystem paths use backslashes (`\`) which can be confused
/// with glob escape sequences. By routing literal-looking paths through
/// a simple `exists()` + `read_dir()` check, we avoid false glob parsing
/// errors entirely. Only patterns containing `*`, `?`, `[`, or `]` go
/// through `expand_glob_patterns` (which uses the glob engine).
fn resolve_literal_patterns(
    patterns: Option<Vec<Spanned<NuGlob>>>,
    args: &Args,
    cwd: &Path,
) -> Result<Vec<PathBuf>, ShellError> {
    let span = args.call_span;

    match patterns {
        // ---- No pattern (bare `uls`) -------------------------------------
        None => {
            if !args.directory {
                // Check if cwd is empty — if so, return empty.
                let mut entries = cwd
                    .read_dir()
                    .map_err(|err| ShellError::Io(IoError::new(err, span, cwd.to_path_buf())))?;
                if entries.next().is_none() {
                    return Ok(Vec::new());
                }
            }
            Ok(vec![cwd.to_path_buf()])
        }
        // ---- One or more explicit paths ----------------------------------
        Some(pats) => {
            let mut paths = Vec::new();
            for pat in pats {
                // Expand tildes and environment variables in the path string.
                let resolved = expand_path_with(pat.item.as_ref(), cwd, pat.item.is_expand());

                // Reject non-existent paths.
                if !resolved.exists() {
                    return Err(ShellError::Generic(
                        GenericError::new(
                            format!("No matches found for {:?}", pat.item.as_ref()),
                            "Pattern, file or folder not found",
                            pat.span,
                        )
                        .with_help("no matches found"),
                    ));
                }

                // If the resolved path is a directory and --directory is
                // not set, check whether it's empty (empty dirs yield
                // no results).
                if !args.directory && resolved.is_dir() {
                    let mut entries = resolved.read_dir().map_err(|err| {
                        ShellError::Io(IoError::new(err, pat.span, resolved.clone()))
                    })?;
                    if entries.next().is_none() {
                        continue;
                    }
                }

                paths.push(resolved);
            }
            Ok(paths)
        }
    }
}

// ============================================================================
// Pipeline metadata helper
// ============================================================================

/// Constructs `PipelineMetadata` for the command output.
///
/// This metadata tells the nushell table renderer which columns to
/// prioritise when the terminal width is limited. For non-long listings,
/// the "name" column gets width priority so filenames are shown even
/// in narrow terminals.
fn ls_pipeline_metadata(span: Span, long: bool) -> PipelineMetadata {
    let mut metadata = PipelineMetadata {
        // path_columns marks the "name" column as containing filesystem
        // paths, enabling path-specific rendering (e.g. clickable links
        // in supported terminals).
        path_columns: vec!["name".to_string()],
        ..Default::default()
    };

    if !long {
        // When not in long mode, the name column is the only interesting
        // data, so give it width priority.
        metadata.set_table_width_priority_columns(span, ["name"]);
    }

    metadata
}

// ============================================================================
// uu_ls configuration builder
// ============================================================================

/// Translates nushell `Args` into a uu_ls `Config` by constructing clap
/// command-line arguments and parsing them through uu_ls's own argument parser.
///
/// This indirection exists because uu_ls exposes its configuration via
/// clap argument parsing rather than a builder API. We synthesise argv
/// entries that correspond to what uu_ls expects, then convert the
/// parsed `ArgMatches` into a `Config`.
///
/// The `force_directory` parameter:
/// --------------------------------
/// When `true` (used for glob-expanded paths), the `-d` flag is forced on
/// so that uu_ls shows each directory path as an entry rather than
/// descending into it and listing its children. This is correct because:
///   - Glob expansion already resolved exactly which paths exist.
///   - When a user writes `uls **/*.rs`, they want a flat list of .rs files,
///     not a directory tree — directories containing .rs files should be
///     shown as entries, not expanded.
fn build_uu_config(args: &Args, force_directory: bool) -> Result<Config, ShellError> {
    // The first argument is always the program name (convention).
    let mut uu_args = vec!["ls".to_string()];

    // ---- Map nushell flags to uu_ls flags --------------------------------
    //
    // nushell's --all flag shows hidden files but NOT the special entries
    // `.` and `..`. This corresponds to GNU ls's --almost-all (-A), not
    // --all (-a). We map to -A accordingly.
    if args.all {
        uu_args.push("--almost-all".to_string());
    }

    if args.long {
        uu_args.push("-l".to_string());
    }

    // Force -d when either --directory was requested by the user OR when
    // we're listing glob-expanded paths (see force_directory doc above).
    if args.directory || force_directory {
        uu_args.push("-d".to_string());
    }

    // ---- Parse through uu_ls's clap app ---------------------------------
    let matches = uu_ls::uu_app()
        .try_get_matches_from(&uu_args)
        .map_err(|e| {
            ShellError::Generic(GenericError::new(
                "Failed to build ls configuration",
                e.to_string(),
                args.call_span,
            ))
        })?;

    // Convert clap ArgMatches → uu_ls Config. This can fail if the
    // matches are internally inconsistent (shouldn't happen here since
    // we constructed them ourselves, but we handle it defensively).
    Config::from(&matches).map_err(|e| {
        ShellError::Generic(GenericError::new(
            "Failed to build ls configuration",
            e.to_string(),
            args.call_span,
        ))
    })
}

// ============================================================================
// Sequential listing
// ============================================================================

/// Lists all entries by passing the full path list to uu_ls in a single call.
///
/// This is the simpler, single-threaded code path. Steps:
/// 1. Convert `Vec<PathBuf>` to `Vec<&Path>` (uu_ls borrows paths).
/// 2. Create a `StreamingOutput` collector.
/// 3. Call `uu_ls::list_with_output()` — uu_ls reads metadata for each path
///    (symlink_metadata on each file), applies the config flags, and pushes
///    EntryInfo records into the collector. This is a synchronous call: it
///    processes all paths on the current thread.
/// 4. Extract collected `Vec<EntryInfo>` via `into_entries()`.
/// 5. Convert each `EntryInfo` to a nushell `Value` via `entry_info_to_value()`.
/// 6. Sort by name so results are in a deterministic, user-friendly order.
fn list_sequential(
    paths: Vec<PathBuf>,
    config: &Config,
    args: &Args,
    cwd: &Path,
    has_glob_meta: bool,
) -> Result<Vec<Value>, ShellError> {
    let path_refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let mut collector = StreamingOutput::new();

    // uu_ls::list_with_output reads metadata and fills the collector.
    // On error (e.g. permission denied for a path), uu_ls generates an
    // EntryInfo with error information rather than failing the whole call,
    // but if the error is catastrophic (e.g. bad config) it returns Err.
    uu_ls::list_with_output(path_refs, config, &mut collector).map_err(|e| {
        ShellError::Generic(GenericError::new(
            "Error listing directory",
            e.to_string(),
            args.call_span,
        ))
    })?;

    let entries_list = collector.into_entries();
    let mut values: Vec<Value> = entries_list
        .iter()
        .map(|entry| entry_info_to_value(entry, args, cwd, has_glob_meta))
        .collect();

    // Sort by display name to ensure deterministic, alphabetically ordered output.
    values.sort_by(sort_values_by_name);
    Ok(values)
}

// ============================================================================
// Parallel listing (chunked)
// ============================================================================

/// Lists entries using chunked parallelism.
///
/// Design rationale:
/// ------------------
/// The naive approach — spawning one thread per file — is catastrophic for
/// large directories (e.g. 1700+ files) because the thread-spawn overhead
/// dwarfs the actual metadata-reading time.
///
/// Instead, we:
/// 1. Divide the `paths` list into N roughly-equal chunks, where N =
///    `available_parallelism()` (typically the number of CPU cores).
/// 2. Spawn one thread per chunk (so N threads total, not N-per-file).
/// 3. Each thread calls `uu_ls::list_with_output()` on its chunk in a single
///    batch — uu_ls already knows how to efficiently process a list of paths.
/// 4. Results are collected via an mpsc channel.
/// 5. Merged results are re-sorted (uu_ls sorts within each chunk, but
///    chunks aren't partitioned by name order, so the merged list needs
///    a global sort).
///
/// Critical detail — the `drop(tx)` call:
/// ---------------------------------------
/// The original `tx` sender (created by `mpsc::channel()`) is **not** moved
/// into any spawned thread — only clones are sent. If we don't `drop(tx)`,
/// the channel has one live sender (the original) plus the cloned senders
/// in the threads. When all threads finish and their scoped clones drop,
/// the original `tx` is still alive, so `rx.into_iter()` blocks forever
/// waiting for more messages. This was the root cause of the "parallel hang"
/// bug. `drop(tx)` ensures the channel is fully closed when threads complete.
fn list_parallel(
    paths: Vec<PathBuf>,
    config: &Config,
    args: &Args,
    cwd: &Path,
    has_glob_meta: bool,
) -> Result<Vec<Value>, ShellError> {
    let num_paths = paths.len();

    // Determine thread count: available parallelism, minimum 1, clamped to
    // the number of paths (no point spawning 16 threads for 3 files).
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(num_paths);

    // Fall back to sequential when there's nothing to parallelise.
    if num_threads <= 1 {
        return list_sequential(paths, config, args, cwd, has_glob_meta);
    }

    // Ceiling division: ensures the last chunk gets any remainder paths
    // rather than being short by up to (num_threads - 1) entries.
    let chunk_size = (num_paths + num_threads - 1) / num_threads;

    // Channel: each thread sends back a Vec<EntryInfo> for its chunk.
    let (tx, rx) = mpsc::channel::<Vec<EntryInfo>>();

    // std::thread::scope ensures all spawned threads complete before
    // the scope exits, giving us safe access to borrowed data (config,
    // args, cwd) without needing Arc or lifetimes gymnastics.
    thread::scope(|s| {
        for chunk in paths.chunks(chunk_size) {
            let tx = tx.clone();
            let chunk: Vec<PathBuf> = chunk.to_vec();
            s.spawn(move || {
                let mut sink = StreamingOutput::new();
                let path_refs: Vec<&Path> = chunk.iter().map(|p| p.as_path()).collect();
                // Silently swallow per-chunk errors: a single chunk failure
                // shouldn't abort the entire listing. The chunk's entries
                // will simply be empty.
                let _ = uu_ls::list_with_output(path_refs, config, &mut sink);
                let _ = tx.send(sink.into_entries());
            });
        }
    });

    // ---- CRITICAL: drop the original sender so the iterator terminates ----
    drop(tx);

    // Flatten all chunks into a single Vec<EntryInfo>.
    let entries: Vec<EntryInfo> = rx.into_iter().flatten().collect();

    // Convert to Values and sort globally.
    let mut values: Vec<Value> = entries
        .iter()
        .map(|entry| entry_info_to_value(entry, args, cwd, has_glob_meta))
        .collect();

    values.sort_by(sort_values_by_name);
    Ok(values)
}

// ============================================================================
// Value sorting helper
// ============================================================================

/// Comparator for sorting nushell `Value::Record` rows by their `"name"` field.
///
/// Used after both sequential and parallel listing to ensure deterministic,
/// alphabetically ordered output. Extracts the `"name"` string from each
/// record's first column and performs a simple string comparison.
fn sort_values_by_name(a: &Value, b: &Value) -> std::cmp::Ordering {
    let a_name = a
        .as_record()
        .ok()
        .and_then(|r| r.get("name"))
        .and_then(|v| v.as_str().ok())
        .unwrap_or("");
    let b_name = b
        .as_record()
        .ok()
        .and_then(|r| r.get("name"))
        .and_then(|v| v.as_str().ok())
        .unwrap_or("");
    a_name.cmp(b_name)
}

// ============================================================================
// EntryInfo → Value conversion
// ============================================================================

/// Converts a uu_ls `EntryInfo` into a nushell `Value::Record` row.
///
/// This is the core serialisation function. It maps uu_ls metadata fields
/// to nushell's column schema, applying nushell-specific transformations:
///
/// Schema (columns):
/// - `name` (string): Display name (see `compute_display_name`).
/// - `type` (string): "dir", "file", "symlink", "pipe", "socket", etc.,
///    or MIME type string when --mime-type is active.
/// - `target` (string | nothing): Symlink target path (only in --long mode).
/// - `size` (filesize): File size in bytes, or recursive directory size
///    when --du is active for directories.
/// - `readonly` (bool): Whether the file is read-only (--long only).
/// - `mode` (string): Unix permission mode string, e.g. "rwxr-xr-x"
///    (unix only, --long only).
/// - `num_links` (int): Number of hard links (unix only, --long only).
/// - `inode` (int): Inode number (unix only, --long only).
/// - `user` (string | int): Owner user name, falling back to uid
///    (unix only, --long only).
/// - `group` (string | int): Owner group name, falling back to gid
///    (unix only, --long only).
/// - `created` (date | nothing): Creation timestamp (--long only;
///    may be nothing on filesystems that don't support it).
/// - `accessed` (date | nothing): Last access timestamp (--long only).
/// - `modified` (date | nothing): Last modification timestamp.
fn entry_info_to_value(entry: &EntryInfo, args: &Args, cwd: &Path, has_glob_meta: bool) -> Value {
    let span = args.call_span;
    let mut record = Record::new();

    // ---- name column -----------------------------------------------------
    // Compute the display name based on flags (short_names, full_paths,
    // command_line vs glob, deep-relative escape).
    let display_name = compute_display_name(entry, args, cwd, has_glob_meta);
    record.push(
        "name",
        Value::string(escape_filename_control_chars(&display_name), span),
    );

    // ---- type column -----------------------------------------------------
    // Determine the file type string. If --mime-type is active and the
    // base type is "file", use mime_guess to determine a MIME type from
    // the filename extension (e.g. "text/plain" for .txt).
    let file_type_str = if let Some(ref ft) = entry.file_type {
        let base_type = file_type_from_ft(ft);
        if args.use_mime_type && base_type == "file" {
            mime_guess::from_path(entry.path.as_os_str())
                .first()
                .map(|m| m.essence_str().to_string())
                .unwrap_or_else(|| base_type.to_string())
        } else {
            base_type.to_string()
        }
    } else {
        "unknown".to_string()
    };
    record.push("type", Value::string(file_type_str, span));

    // ---- target column (symlinks, only in --long mode) -------------------
    if args.long {
        record.push(
            "target",
            if entry.is_symlink() {
                match entry.path.read_link() {
                    Ok(target) => {
                        // When --full-paths is active and the symlink target
                        // is relative, resolve it relative to the symlink's
                        // parent directory to produce an absolute target path.
                        let target_str = if args.full_paths && target.is_relative() {
                            entry
                                .path
                                .parent()
                                .unwrap_or(&entry.path)
                                .join(&target)
                                .to_string_lossy()
                                .to_string()
                        } else {
                            target.to_string_lossy().to_string()
                        };
                        Value::string(escape_filename_control_chars(&target_str), span)
                    }
                    Err(_) => Value::string("Could not obtain target file's path", span),
                }
            } else {
                Value::nothing(span)
            },
        );
    }

    // ---- Metadata-derived columns ----------------------------------------
    if let Some(ref md) = entry.metadata {
        // --long-only columns: readonly, mode, num_links, inode, user, group
        if args.long {
            record.push("readonly", Value::bool(md.permissions().readonly(), span));

            // Unix-specific columns: mode string, hard link count, inode,
            // user name/uid, group name/gid. These are conditionally
            // compiled because the underlying metadata methods (nlink,
            // ino, uid, gid) are Unix-only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = md.permissions().mode();
                record.push(
                    "mode",
                    Value::string(umask::Mode::from(mode).to_string(), span),
                );
                record.push("num_links", Value::int(md.nlink() as i64, span));
                record.push("inode", Value::int(md.ino() as i64, span));

                // Resolve uid to user name. Falls back to numeric uid if
                // the user can't be looked up (e.g. non-local user).
                record.push(
                    "user",
                    if let Some(user) =
                        nu_utils::filesystem::users::get_user_by_uid(md.uid().into())
                    {
                        Value::string(user.name, span)
                    } else {
                        Value::int(md.uid().into(), span)
                    },
                );

                // Resolve gid to group name, falling back to numeric gid.
                record.push(
                    "group",
                    if let Some(group) =
                        nu_utils::filesystem::users::get_group_by_gid(md.gid().into())
                    {
                        Value::string(group.name, span)
                    } else {
                        Value::int(md.gid().into(), span)
                    },
                );
            }
        }

        // ---- size column -------------------------------------------------
        // For directories with --du, compute the recursive size using
        // DirInfo (which walks the directory tree). Otherwise, use the
        // metadata's st_size / file length directly.
        record.push(
            "size",
            if md.is_dir() {
                if args.du {
                    // DirBuilder with no special settings: just collects
                    // apparent sizes (not disk usage).
                    let params = DirBuilder::new(Span::new(0, 2), None, false, None, false);
                    if let Ok(dir_info) =
                        DirInfo::new(&entry.path, &params, None, span, &Signals::empty())
                    {
                        Value::filesize(dir_info.get_size() as i64, span)
                    } else {
                        // Fall back to metadata size if DirInfo fails
                        // (e.g. permission denied on subdirectories).
                        Value::filesize(md.len() as i64, span)
                    }
                } else {
                    Value::filesize(md.len() as i64, span)
                }
            } else {
                Value::filesize(md.len() as i64, span)
            },
        );

        // --long-only timestamp columns: created, accessed
        if args.long {
            // Creation time: not all filesystems support this (e.g. ext4
            // without crtime, some network filesystems). Returns nothing
            // when unavailable.
            record.push(
                "created",
                md.created()
                    .ok()
                    .and_then(try_convert_to_local_date_time)
                    .map(|dt| Value::date(dt.with_timezone(dt.offset()), span))
                    .unwrap_or_else(|| Value::nothing(span)),
            );
            // Access time: may be disabled by the filesystem or mount
            // options (e.g. `noatime`). Returns nothing when unavailable.
            record.push(
                "accessed",
                md.accessed()
                    .ok()
                    .and_then(try_convert_to_local_date_time)
                    .map(|dt| Value::date(dt.with_timezone(dt.offset()), span))
                    .unwrap_or_else(|| Value::nothing(span)),
            );
        }

        // ---- modified column (always present) ---------------------------
        // Last modification time. This is the most universally supported
        // timestamp; it's available on virtually all filesystems.
        record.push(
            "modified",
            md.modified()
                .ok()
                .and_then(try_convert_to_local_date_time)
                .map(|dt| Value::date(dt.with_timezone(dt.offset()), span))
                .unwrap_or_else(|| Value::nothing(span)),
        );
    }

    Value::record(record, span)
}

// ============================================================================
// Display name computation
// ============================================================================

/// Computes the display name (the string shown in the `name` column) for
/// a filesystem entry, applying nushell's display-name rules.
///
/// Display logic (checked in order):
/// 1. `--short-names`: Only the filename component (last segment), e.g.
///    `file.txt` instead of `src/lib/file.txt`.
/// 2. `--full-paths`: Always show the absolute path.
/// 3. `command_line && !has_glob_meta`: The path was typed literally by the
///    user (not from glob expansion). Show it as-is if it's absolute,
///    otherwise relativize it to CWD. This handles cases like `uls ..`
///    where the user typed a relative path and expects to see that path
///    reflected in the output.
/// 4. Default (glob results or directory contents): Show a relative path
///    from CWD to the entry. However, if the relative path has 2+ `..`
///    components (meaning the entry is on a completely different branch
///    of the filesystem tree), fall back to showing the full absolute path
///    for clarity.
///
/// The `has_glob_meta` flag:
/// -------------------------
/// When uu_ls lists files, it sets `command_line = true` on every path
/// it receives, because from uu_ls's perspective all paths were "typed
/// by the user". However, paths that came from glob expansion are not
/// user-typed literals — they are discovered by pattern matching. We use
/// `has_glob_meta` to distinguish these cases: glob results should be
/// shown relative to CWD (like `ls` does), not as-is.
fn compute_display_name(entry: &EntryInfo, args: &Args, cwd: &Path, has_glob_meta: bool) -> String {
    // Mode 1: --short-names → basename only
    if args.short_names {
        entry
            .path
            .file_name()
            .map(|os| os.to_string_lossy().to_string())
            .unwrap_or_default()
    // Mode 2: --full-paths → absolute path
    } else if args.full_paths {
        entry.path.to_string_lossy().to_string()
    // Mode 3: Literal user-typed path (not glob expansion)
    // Show as-is if absolute, relativize to CWD if relative.
    } else if entry.command_line && !has_glob_meta {
        if entry.path.is_absolute() {
            entry.path.to_string_lossy().to_string()
        } else {
            make_relative_to_cwd(&entry.path, cwd)
                .to_string_lossy()
                .to_string()
        }
    // Mode 4: Default — relative path from CWD to entry
    } else {
        // Extract the filename (last path component) for joining with prefix.
        let file_name = entry
            .path
            .file_name()
            .map(|os| os.to_string_lossy().to_string())
            .unwrap_or_default();
        let parent = entry.path.parent().unwrap_or(&entry.path);
        let rel_prefix = make_relative_to_cwd(parent, cwd);

        // If the relative prefix is "." (same directory), just show the
        // filename without any prefix.
        if rel_prefix == Path::new(".") || rel_prefix.as_os_str().is_empty() {
            file_name
        // Deep-relative escape: if the relative path has 2 or more ".."
        // components (e.g. "../../other_project/src"), it means the entry
        // is on a very different branch of the filesystem. Showing
        // "../../other_project/src/file.txt" is confusing; instead show
        // the full absolute path for clarity.
        } else if rel_prefix
            .components()
            .filter(|c| *c == std::path::Component::ParentDir)
            .count()
            >= 2
        {
            entry.path.to_string_lossy().to_string()
        } else {
            // Normal case: join the relative prefix with the filename.
            rel_prefix.join(&file_name).to_string_lossy().to_string()
        }
    }
}

// ============================================================================
// Path utility functions
// ============================================================================

/// Strips the Windows long-path prefix (`\\?\`) from a path, if present.
///
/// Windows uses the `\\?\` prefix to enable long paths (>260 characters)
/// and to disable normal path parsing (e.g. treating `/` as a separator).
/// When comparing or relativising paths, this prefix interferes with
/// string-based operations like `diff_paths`. Stripping it first makes
/// path comparisons work correctly regardless of whether the paths were
/// obtained via long-path-aware APIs.
fn strip_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

/// Computes a relative path from `base` to `path`.
///
/// Wraps `diff_paths` with:
/// 1. Verbatim prefix stripping (Windows `\\?\` removal) so paths from
///    different sources (expanded vs direct) can be relativised correctly.
/// 2. Filtering out empty relative paths (when path == base) — returns
///    `"."` instead of an empty string, which is the conventional
///    representation of "the current directory".
fn make_relative_to_cwd(path: &Path, base: &Path) -> PathBuf {
    let path = strip_verbatim_prefix(path);
    let base = strip_verbatim_prefix(base);
    diff_paths(&path, &base)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

// ============================================================================
// Glob metacharacter detection
// ============================================================================

/// Returns `true` if the string contains any glob metacharacters.
///
/// This is used to decide whether a pattern should go through the glob
/// engine (`expand_glob_patterns`) or be treated as a literal path
/// (`resolve_literal_patterns`). We check for the four standard glob
/// metacharacters: `*`, `?`, `[`, `]`.
///
/// Note that `{` and `}` (brace expansion) and `(` / `)` (extended glob)
/// are not checked here because nushell's glob backends don't support them.
fn has_glob_metachars(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[') || s.contains(']')
}

// ============================================================================
// File type → string mapping
// ============================================================================

/// Maps a `std::fs::FileType` to the human-readable string used in the
/// `type` column.
///
/// Standard types:
/// - `dir` — Directory
/// - `file` — Regular file
/// - `symlink` — Symbolic link
///
/// Unix-only additional types (via `FileTypeExt`):
/// - `block device` — Block special device (e.g. `/dev/sda`)
/// - `char device` — Character special device (e.g. `/dev/tty`)
/// - `pipe` — Named pipe / FIFO
/// - `socket` — Unix domain socket
///
/// The function is implemented by checking `is_dir`, `is_file`, and
/// `is_symlink` first (these are available on all platforms), then
/// falling back to the Unix-specific extensions on unix. On non-unix
/// platforms, anything that isn't dir/file/symlink is reported as
/// `"unknown"`, since Windows doesn't have block/char devices, pipes,
/// or sockets as filesystem types in the same sense.
fn file_type_from_ft(ft: &std::fs::FileType) -> String {
    if ft.is_dir() {
        "dir".to_string()
    } else if ft.is_file() {
        "file".to_string()
    } else if ft.is_symlink() {
        "symlink".to_string()
    } else {
        // Unix-only special file types.
        // These are conditionally compiled because the FileTypeExt trait
        // is only available on Unix platforms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if ft.is_block_device() {
                return "block device".to_string();
            } else if ft.is_char_device() {
                return "char device".to_string();
            } else if ft.is_fifo() {
                return "pipe".to_string();
            } else if ft.is_socket() {
                return "socket".to_string();
            }
        }
        "unknown".to_string()
    }
}

// ============================================================================
// Timestamp conversion
// ============================================================================

/// Converts a `SystemTime` (filesystem timestamp) to a local-time `DateTime`.
///
/// This conversion handles several edge cases:
///
/// 1. **Pre-epoch timestamps**: `SystemTime::duration_since(UNIX_EPOCH)`
///    returns `Err` for timestamps before 1970-01-01. We extract the
///    duration from the error and negate it to get a negative Unix timestamp.
///
/// 2. **Sub-second precision**: Filesystem timestamps often have nanosecond
///    precision. We preserve this through `timestamp_opt`.
///
/// 3. **The Windows epoch sentinel**: The Windows filesystem epoch is
///    1601-01-01, which corresponds to Unix timestamp -11644473600.
///    Timestamps at this exact value usually indicate a filesystem that
///    doesn't support the requested timestamp field (e.g. `creation_time`
///    on some network filesystems). We return `None` for this sentinel
///    value, causing the caller to display "nothing" instead of a
///    misleading year-1601 date.
///
/// 4. **Invalid / ambiguous local time**: `Utc.timestamp_opt` can return
///    `None` or `Ambiguous` for timestamps during DST transitions or
///    out-of-range values. We return `None` in these cases.
fn try_convert_to_local_date_time(t: SystemTime) -> Option<DateTime<Local>> {
    // Decompose the SystemTime into seconds and nanoseconds relative to
    // the Unix epoch (1970-01-01 00:00:00 UTC).
    let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
        // Post-epoch timestamp: straightforward.
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        // Pre-epoch timestamp: negate and adjust for nanosecond precision.
        Err(e) => {
            let dur = e.duration();
            let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
            if nsec == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - nsec)
            }
        }
    };

    // Reject the Windows epoch sentinel value (-11644473600).
    const NEG_UNIX_EPOCH: i64 = -11644473600;
    if sec == NEG_UNIX_EPOCH {
        return None;
    }

    // Convert to DateTime via chrono's timestamp_opt, then adjust to local time.
    match Utc.timestamp_opt(sec, nsec) {
        LocalResult::Single(t) => Some(t.with_timezone(&Local)),
        _ => None,
    }
}

// ============================================================================
// Filename control character escaping
// ============================================================================

/// Escapes control characters in a filename so they are displayed visibly
/// rather than being interpreted by the terminal.
///
/// Control characters (U+0000–U+001F and U+007F) in filenames can cause
/// terminal corruption, trigger escape sequences, or be invisible. This
/// function replaces each such character with its `\\u{N}` Unicode escape
/// representation (e.g. `\u{0}` for NUL, `\u{1b}` for ESC).
///
/// Fast path: if no control characters are present, returns the original
/// string without allocation.
///
/// Example: `"hooks\x1bE"` → `"hooks\\u{1b}E"`
fn escape_filename_control_chars(name: &str) -> String {
    // Fast path: skip allocation if no control characters are present.
    if !name.chars().any(|c| c.is_control()) {
        return name.to_string();
    }

    let mut buf = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_control() {
            // Use Rust's built-in Unicode escape (produces `\u{NN}` format).
            buf.extend(c.escape_unicode());
        } else {
            buf.push(c);
        }
    }
    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::escape_filename_control_chars;

    // ---- escape_filename_control_chars tests -----------------------------

    #[test]
    fn escape_filename_control_chars_renders_control_chars_visibly() {
        // ASCII text with no control characters: pass through unchanged.
        assert_eq!(escape_filename_control_chars("hello.txt"), "hello.txt");
        // ESC character (0x1B) → escaped representation.
        assert_eq!(escape_filename_control_chars("hooks\x1bE"), "hooks\\u{1b}E");
        // NUL character (0x00) → escaped.
        assert_eq!(
            escape_filename_control_chars("file\x00name"),
            "file\\u{0}name"
        );
        // Multiple control characters.
        assert_eq!(
            escape_filename_control_chars("\x01a\x02b"),
            "\\u{1}a\\u{2}b"
        );
    }

    // ---- make_relative_to_cwd tests -------------------------------------

    #[test]
    fn make_relative_to_cwd_works_for_subdir() {
        use std::path::Path;
        let base = Path::new("C:\\Temp\\project");
        let path = Path::new("C:\\Temp\\project\\subdir\\file.txt");
        let rel = super::make_relative_to_cwd(path, base);
        assert_eq!(rel.to_string_lossy(), "subdir\\file.txt");
    }

    #[test]
    fn make_relative_to_cwd_works_for_parent() {
        use std::path::Path;
        let base = Path::new("C:\\Temp\\project\\src");
        let path = Path::new("C:\\Temp\\project\\readme.md");
        let rel = super::make_relative_to_cwd(path, base);
        assert_eq!(rel.to_string_lossy(), "..\\readme.md");
    }

    #[test]
    fn make_relative_to_cwd_works_for_self() {
        use std::path::Path;
        let base = Path::new("C:\\Temp\\project");
        let path = Path::new("C:\\Temp\\project");
        let rel = super::make_relative_to_cwd(path, base);
        assert_eq!(rel.to_string_lossy(), ".");
    }

    /// Tests make_relative_to_cwd with actual temp files on disk to ensure
    /// it works with real (possibly verbatim-prefixed) paths.
    #[test]
    fn make_relative_to_cwd_real_temp() {
        use std::fs;

        let tmp = std::env::temp_dir().join("nuls_test_rel");
        let sub = tmp.join("subdir");
        let _ = fs::create_dir_all(&sub);
        let file = sub.join("test.txt");
        fs::write(&file, b"hello").ok();

        // Test with regular paths.
        let rel = super::make_relative_to_cwd(&file, &tmp);
        assert!(
            rel.to_string_lossy().contains("test.txt"),
            "Expected relative path to contain test.txt, got {:?}",
            rel
        );

        // Test with canonicalised (potentially long-path prefixed) paths
        // to ensure strip_verbatim_prefix handles them correctly.
        let canonical_file = std::fs::canonicalize(&file).unwrap_or(file.clone());
        let canonical_tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp.clone());
        let rel2 = super::make_relative_to_cwd(&canonical_file, &canonical_tmp);
        assert!(
            rel2.to_string_lossy().contains("test.txt"),
            "Expected relative path to contain test.txt with canonical paths, got {:?}",
            rel2
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
