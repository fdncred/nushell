use crate::DirBuilder;
use crate::DirInfo;
use chrono::{DateTime, Local, LocalResult, TimeZone, Utc};
use nu_engine::{env::current_dir, CallExt};
use nu_path::{canonicalize_with, expand_path_with, expand_to_real_path};
use nu_protocol::{
    ast::Call,
    engine::{Command, EngineState, Stack},
    Category, DataSource, Example, IntoInterruptiblePipelineData, IntoPipelineData, PipelineData,
    PipelineMetadata, ShellError, Signature, Span, Spanned, SyntaxShape, Type, Value,
};
use pathdiff::diff_paths;
use rayon::prelude::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Component, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct LsGlob;

impl Command for LsGlob {
    fn name(&self) -> &str {
        "lg"
    }

    fn usage(&self) -> &str {
        "List the filenames, sizes, and modification times of items in a directory."
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["dir"]
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build("lg")
            .input_output_types(vec![(Type::Nothing, Type::Table(vec![]))])
            // Using a string instead of a glob pattern shape so it won't auto-expand
            .optional("pattern", SyntaxShape::String, "the glob pattern to use")
            .switch("all", "Show hidden files", Some('a'))
            .switch(
                "long",
                "Get all available columns for each entry (slower; columns are platform-dependent)",
                Some('l'),
            )
            .switch(
                "short-names",
                "Only print the file names, and not the path",
                Some('s'),
            )
            .switch("full-paths", "display paths as absolute paths", Some('f'))
            .switch(
                "du",
                "Display the apparent directory size (\"disk usage\") in place of the directory metadata size",
                Some('d'),
            )
            .switch(
                "directory",
                "List the specified directory itself instead of its contents",
                Some('D'),
            )
            // .switch("mime-type", "Show mime-type in type column instead of 'file' (based on filenames only; files' contents are not examined)", Some('m'))
            .category(Category::FileSystem)
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let all = call.has_flag("all");
        let long = call.has_flag("long");
        let short_names = call.has_flag("short-names");
        let full_paths = call.has_flag("full-paths");
        let du = call.has_flag("du");
        let directory = call.has_flag("directory");
        let use_mime_type = call.has_flag("mime-type");
        let ctrl_c = engine_state.ctrlc.clone();
        let call_span = call.head;
        let cwd = current_dir(engine_state, stack)?;

        let pattern_arg: Option<Spanned<String>> = call.opt(engine_state, stack, 0)?;

        let pattern_arg = {
            if let Some(path) = pattern_arg {
                Some(Spanned {
                    item: nu_utils::strip_ansi_string_unlikely(path.item),
                    span: path.span,
                })
            } else {
                pattern_arg
            }
        };

        let (pathbuf, p_tag, absolute_path, prefix_only, patterns_only) = match pattern_arg {
            Some(p) => {
                let p_tag = p.span;
                let (mut prefix_only, mut pattern_only) = get_prefix(&p, &cwd)?;
                // eprintln!(
                //     "prefix_only: {:?}, pattern_only: {:?}",
                //     prefix_only, pattern_only
                // );
                let mut p = expand_to_real_path(p.item);

                let expanded = nu_path::expand_path_with(&p, &cwd);
                // Avoid checking and pushing "*" to the path when directory (do not show contents) flag is true
                if !directory && expanded.is_dir() {
                    if permission_denied(&p) {
                        #[cfg(unix)]
                        let error_msg = format!(
                            "The permissions of {:o} do not allow access for this user",
                            expanded
                                .metadata()
                                .expect(
                                    "this shouldn't be called since we already know there is a dir"
                                )
                                .permissions()
                                .mode()
                                & 0o0777
                        );
                        #[cfg(not(unix))]
                        let error_msg = String::from("Permission denied");
                        return Err(ShellError::GenericError(
                            "Permission denied".to_string(),
                            error_msg,
                            Some(p_tag),
                            None,
                            Vec::new(),
                        ));
                    }
                    if is_empty_dir(&expanded) {
                        return Ok(Value::list(vec![], call_span).into_pipeline_data());
                    }
                    p.push("*");
                }
                let absolute_path = p.is_absolute();
                // eprintln!("p: {:?} expanded: {:?}", &p, &expanded);
                if p.display().to_string() != expanded.display().to_string()
                    && p.ends_with("*")
                    && !expanded.ends_with("*")
                {
                    prefix_only = Some(expanded.clone());
                    pattern_only = vec!["*".to_string()]
                }
                (p, p_tag, absolute_path, prefix_only, pattern_only)
            }
            None => {
                // Avoid pushing "*" to the default path when directory (do not show contents) flag is true
                if directory {
                    (
                        PathBuf::from("."),
                        call_span,
                        false,
                        Some(cwd.clone()),
                        vec![".".to_string()],
                    )
                } else if is_empty_dir(current_dir(engine_state, stack)?) {
                    return Ok(Value::list(vec![], call_span).into_pipeline_data());
                } else {
                    (
                        PathBuf::from("*"),
                        call_span,
                        false,
                        Some(cwd.clone()),
                        vec!["*".to_string()],
                    )
                }
            }
        };

        let hidden_dir_specified = is_hidden_dir(&pathbuf);
        let max_depth = if patterns_only.iter().any(|f| f.contains("**")) {
            usize::MAX
        } else {
            1usize
        };

        let prefix = match prefix_only {
            Some(pref) => pref,
            None => cwd.clone(),
        };

        let paths = match globwalk::GlobWalkerBuilder::from_patterns(&prefix, &patterns_only[..])
            .min_depth(0)
            .max_depth(max_depth)
            // .follow_links(true)
            // .max_open(10)
            // // .sort_by(cmp)
            // .contents_first(true)
            // // .file_type(file_type)
            .build()
        {
            Ok(paths) => paths.into_iter(),
            Err(_) => {
                return Err(ShellError::GenericError(
                    format!("No matches found for {}", &pathbuf.display().to_string()),
                    "Pattern, file or folder not found".to_string(),
                    Some(p_tag),
                    Some("no matches found".to_string()),
                    Vec::new(),
                ));
            }
        };
        // for path in paths.into_iter() {
        //     let p = match path {
        //         Ok(p) => p,
        //         Err(_) => {
        //             return Err(ShellError::GenericError(
        //                 format!("No matches found for {:?}", pat_arg_clone),
        //                 "Pattern, file or folder not found".to_string(),
        //                 Some(p_tag),
        //                 Some("no matches found".to_string()),
        //                 Vec::new(),
        //             ));
        //         }
        //     };
        //     let meta = p.metadata().unwrap();
        //     eprintln!(
        //         "P:{}, F:{} D:{} T:{}|{}|{} M:{:?}|{:?}|{:?}|{}|{}|{}|{}|{:?}|{:?} S:{}",
        //         p.path().display(),
        //         p.file_name().to_string_lossy(),
        //         p.depth(),
        //         p.file_type().is_dir(),
        //         p.file_type().is_file(),
        //         p.file_type().is_symlink(),
        //         meta.accessed(),
        //         meta.created(),
        //         meta.file_type(),
        //         meta.is_dir(),
        //         meta.is_file(),
        //         meta.is_symlink(),
        //         meta.len(),
        //         meta.modified(),
        //         meta.permissions(),
        //         p.path_is_symlink()
        //     );
        // }
        // Ok(Value::nothing(call_span).into_pipeline_data())

        // let mut paths_peek = paths.peekable();
        // if paths_peek.peek().is_none() {
        //     return Err(ShellError::GenericError(
        //         format!("No matches found for {}", &pathbuf.display().to_string()),
        //         "Pattern, file or folder not found".to_string(),
        //         Some(p_tag),
        //         Some("no matches found".to_string()),
        //         Vec::new(),
        //     ));
        // }

        let hidden_dirs = Arc::new(Mutex::new(Vec::new()));

        Ok(paths
            .into_iter()
            .par_bridge()
            .filter_map(move |x| match x {
                Ok(path) => {
                    let metadata = match path.metadata() {
                        Ok(metadata) => Some(metadata),
                        Err(_) => None,
                    };
                    {
                        let hidden_dir_clone = Arc::clone(&hidden_dirs);
                        let hidden_dir_mutex = hidden_dir_clone.lock().unwrap();
                        if path_contains_hidden_folder(&path.path(), &hidden_dir_mutex) {
                            return None;
                        }
                    }
                    if !all && !hidden_dir_specified && is_hidden_dir(&path.path()) {
                        if path.file_type().is_dir() {
                            let hidden_dir_clone = Arc::clone(&hidden_dirs);
                            let mut hidden_dir_mutex = hidden_dir_clone.lock().unwrap();
                            hidden_dir_mutex.push(path.path().to_path_buf());
                        }
                        return None;
                    }

                    let prefix = Some(path.path().parent().unwrap_or_else(|| Path::new("")));

                    let display_name = if short_names {
                        Some(path.file_name().to_string_lossy().to_string())
                    } else if full_paths || absolute_path {
                        Some(path.path().to_string_lossy().to_string())
                    } else if let Some(prefix) = &prefix {
                        if let Ok(remainder) = path.path().strip_prefix(prefix) {
                            if directory {
                                // When the path is the same as the cwd, path_diff should be "."
                                let path_diff = if let Some(path_diff_not_dot) =
                                    diff_paths(&path.path(), &cwd)
                                {
                                    let path_diff_not_dot = path_diff_not_dot.to_string_lossy();
                                    if path_diff_not_dot.is_empty() {
                                        ".".to_string()
                                    } else {
                                        path_diff_not_dot.to_string()
                                    }
                                } else {
                                    path.path().to_string_lossy().to_string()
                                };

                                Some(path_diff)
                            } else {
                                let new_prefix = if let Some(pfx) = diff_paths(prefix, &cwd) {
                                    pfx
                                } else {
                                    prefix.to_path_buf()
                                };

                                Some(new_prefix.join(remainder).to_string_lossy().to_string())
                            }
                        } else {
                            Some(path.path().to_string_lossy().to_string())
                        }
                    } else {
                        Some(path.path().to_string_lossy().to_string())
                    }
                    .ok_or_else(|| {
                        ShellError::GenericError(
                            format!(
                                "Invalid file name: {:}",
                                path.path().to_string_lossy().to_string()
                            ),
                            "invalid file name".into(),
                            Some(call_span),
                            None,
                            Vec::new(),
                        )
                    });

                    match display_name {
                        Ok(name) => {
                            let entry = dir_entry_dict(
                                &path.path(),
                                &name,
                                metadata.as_ref(),
                                call_span,
                                long,
                                du,
                                ctrl_c.clone(),
                                use_mime_type,
                            );
                            match entry {
                                Ok(value) => Some(value),
                                Err(err) => Some(Value::Error {
                                    error: Box::new(err),
                                }),
                            }
                        }
                        Err(err) => Some(Value::Error {
                            error: Box::new(err),
                        }),
                    }
                }
                _ => Some(Value::Nothing { span: call_span }),
            })
            .collect::<Vec<_>>()
            .into_iter()
            .into_pipeline_data_with_metadata(
                Box::new(PipelineMetadata {
                    data_source: DataSource::Ls,
                }),
                engine_state.ctrlc.clone(),
            ))

        // Ok(Value::nothing(call_span).into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example> {
        vec![
            Example {
                description: "List visible files in the current directory",
                example: "ls",
                result: None,
            },
            Example {
                description: "List visible files in a subdirectory",
                example: "ls subdir",
                result: None,
            },
            Example {
                description: "List visible files with full path in the parent directory",
                example: "ls -f ..",
                result: None,
            },
            Example {
                description: "List Rust files",
                example: "ls *.rs",
                result: None,
            },
            Example {
                description: "List files and directories whose name do not contain 'bar'",
                example: "ls -s | where name !~ bar",
                result: None,
            },
            Example {
                description: "List all dirs in your home directory",
                example: "ls -a ~ | where type == dir",
                result: None,
            },
            Example {
                description:
                    "List all dirs in your home directory which have not been modified in 7 days",
                example: "ls -as ~ | where type == dir and modified < ((date now) - 7day)",
                result: None,
            },
            Example {
                description: "List given paths and show directories themselves",
                example: "['/path/to/directory' '/path/to/file'] | each {|| ls -D $in } | flatten",
                result: None,
            },
        ]
    }
}

fn permission_denied(dir: impl AsRef<Path>) -> bool {
    match dir.as_ref().read_dir() {
        Err(e) => matches!(e.kind(), std::io::ErrorKind::PermissionDenied),
        Ok(_) => false,
    }
}

fn is_empty_dir(dir: impl AsRef<Path>) -> bool {
    match dir.as_ref().read_dir() {
        Err(_) => true,
        Ok(mut s) => s.next().is_none(),
    }
}

fn is_hidden_dir(dir: impl AsRef<Path>) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        if let Ok(metadata) = dir.as_ref().metadata() {
            let attributes = metadata.file_attributes();
            // https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
            (attributes & 0x2) != 0
        } else {
            false
        }
    }

    #[cfg(not(windows))]
    {
        dir.as_ref()
            .file_name()
            .map(|name| name.to_string_lossy().starts_with('.'))
            .unwrap_or(false)
    }
}

fn path_contains_hidden_folder(path: &Path, folders: &[PathBuf]) -> bool {
    if folders.iter().any(|p| path.starts_with(p.as_path())) {
        return true;
    }
    false
}

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;

pub fn get_file_type(md: &std::fs::Metadata, display_name: &str, use_mime_type: bool) -> String {
    let ft = md.file_type();
    let mut file_type = "unknown";
    if ft.is_dir() {
        file_type = "dir";
    } else if ft.is_file() {
        file_type = "file";
    } else if ft.is_symlink() {
        file_type = "symlink";
    } else {
        #[cfg(unix)]
        {
            if ft.is_block_device() {
                file_type = "block device";
            } else if ft.is_char_device() {
                file_type = "char device";
            } else if ft.is_fifo() {
                file_type = "pipe";
            } else if ft.is_socket() {
                file_type = "socket";
            }
        }
    }
    if use_mime_type {
        let guess = mime_guess::from_path(display_name);
        let mime_guess = match guess.first() {
            Some(mime_type) => mime_type.essence_str().to_string(),
            None => "unknown".to_string(),
        };
        if file_type == "file" {
            mime_guess
        } else {
            file_type.to_string()
        }
    } else {
        file_type.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dir_entry_dict(
    filename: &std::path::Path, // absolute path
    display_name: &str,         // file name to be displayed
    metadata: Option<&std::fs::Metadata>,
    span: Span,
    long: bool,
    du: bool,
    ctrl_c: Option<Arc<AtomicBool>>,
    use_mime_type: bool,
) -> Result<Value, ShellError> {
    #[cfg(windows)]
    if metadata.is_none() {
        return Ok(windows_helper::dir_entry_dict_windows_fallback(
            filename,
            display_name,
            span,
            long,
        ));
    }

    let mut cols = vec![];
    let mut vals = vec![];
    let mut file_type = "unknown".to_string();

    cols.push("name".into());
    vals.push(Value::String {
        val: display_name.to_string(),
        span,
    });

    if let Some(md) = metadata {
        file_type = get_file_type(md, display_name, use_mime_type);
        cols.push("type".into());
        vals.push(Value::String {
            val: file_type.clone(),
            span,
        });
    } else {
        cols.push("type".into());
        vals.push(Value::nothing(span));
    }

    if long {
        cols.push("target".into());
        if let Some(md) = metadata {
            if md.file_type().is_symlink() {
                if let Ok(path_to_link) = filename.read_link() {
                    vals.push(Value::String {
                        val: path_to_link.to_string_lossy().to_string(),
                        span,
                    });
                } else {
                    vals.push(Value::String {
                        val: "Could not obtain target file's path".to_string(),
                        span,
                    });
                }
            } else {
                vals.push(Value::nothing(span));
            }
        }
    }

    if long {
        if let Some(md) = metadata {
            cols.push("readonly".into());
            vals.push(Value::Bool {
                val: md.permissions().readonly(),
                span,
            });

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let mode = md.permissions().mode();
                cols.push("mode".into());
                vals.push(Value::String {
                    val: umask::Mode::from(mode).to_string(),
                    span,
                });

                let nlinks = md.nlink();
                cols.push("num_links".into());
                vals.push(Value::Int {
                    val: nlinks as i64,
                    span,
                });

                let inode = md.ino();
                cols.push("inode".into());
                vals.push(Value::Int {
                    val: inode as i64,
                    span,
                });

                cols.push("uid".into());
                if let Some(user) = users::get_user_by_uid(md.uid()) {
                    vals.push(Value::String {
                        val: user.name().to_string_lossy().into(),
                        span,
                    });
                } else {
                    vals.push(Value::Int {
                        val: md.uid() as i64,
                        span,
                    })
                }

                cols.push("group".into());
                if let Some(group) = users::get_group_by_gid(md.gid()) {
                    vals.push(Value::String {
                        val: group.name().to_string_lossy().into(),
                        span,
                    });
                } else {
                    vals.push(Value::Int {
                        val: md.gid() as i64,
                        span,
                    })
                }
            }
        }
    }

    cols.push("size".to_string());
    if let Some(md) = metadata {
        let zero_sized = file_type == "pipe"
            || file_type == "socket"
            || file_type == "char device"
            || file_type == "block device";

        if md.is_dir() {
            if du {
                let params = DirBuilder::new(Span::new(0, 2), None, false, None, false);
                let dir_size = DirInfo::new(filename, &params, None, ctrl_c).get_size();

                vals.push(Value::Filesize {
                    val: dir_size as i64,
                    span,
                });
            } else {
                let dir_size: u64 = md.len();

                vals.push(Value::Filesize {
                    val: dir_size as i64,
                    span,
                });
            };
        } else if md.is_file() {
            vals.push(Value::Filesize {
                val: md.len() as i64,
                span,
            });
        } else if md.file_type().is_symlink() {
            if let Ok(symlink_md) = filename.symlink_metadata() {
                vals.push(Value::Filesize {
                    val: symlink_md.len() as i64,
                    span,
                });
            } else {
                vals.push(Value::nothing(span));
            }
        } else {
            let value = if zero_sized {
                Value::Filesize { val: 0, span }
            } else {
                Value::nothing(span)
            };
            vals.push(value);
        }
    } else {
        vals.push(Value::nothing(span));
    }

    if let Some(md) = metadata {
        if long {
            cols.push("created".to_string());
            {
                let mut val = Value::nothing(span);
                if let Ok(c) = md.created() {
                    if let Some(local) = try_convert_to_local_date_time(c) {
                        val = Value::Date {
                            val: local.with_timezone(local.offset()),
                            span,
                        };
                    }
                }
                vals.push(val);
            }

            cols.push("accessed".to_string());
            {
                let mut val = Value::nothing(span);
                if let Ok(a) = md.accessed() {
                    if let Some(local) = try_convert_to_local_date_time(a) {
                        val = Value::Date {
                            val: local.with_timezone(local.offset()),
                            span,
                        };
                    }
                }
                vals.push(val);
            }
        }

        cols.push("modified".to_string());
        {
            let mut val = Value::nothing(span);
            if let Ok(m) = md.modified() {
                if let Some(local) = try_convert_to_local_date_time(m) {
                    val = Value::Date {
                        val: local.with_timezone(local.offset()),
                        span,
                    };
                }
            }
            vals.push(val);
        }
    } else {
        if long {
            cols.push("created".to_string());
            vals.push(Value::nothing(span));

            cols.push("accessed".to_string());
            vals.push(Value::nothing(span));
        }

        cols.push("modified".to_string());
        vals.push(Value::nothing(span));
    }

    Ok(Value::Record { cols, vals, span })
}

// TODO: can we get away from local times in `ls`? internals might be cleaner if we worked in UTC
// and left the conversion to local time to the display layer
fn try_convert_to_local_date_time(t: SystemTime) -> Option<DateTime<Local>> {
    // Adapted from https://github.com/chronotope/chrono/blob/v0.4.19/src/datetime.rs#L755-L767.
    let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        Err(e) => {
            // unlikely but should be handled
            let dur = e.duration();
            let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
            if nsec == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - nsec)
            }
        }
    };

    match Utc.timestamp_opt(sec, nsec) {
        LocalResult::Single(t) => Some(t.with_timezone(&Local)),
        _ => None,
    }
}

// #[cfg(windows)] is just to make Clippy happy, remove if you ever want to use this on other platforms
#[cfg(windows)]
fn unix_time_to_local_date_time(secs: i64) -> Option<DateTime<Local>> {
    match Utc.timestamp_opt(secs, 0) {
        LocalResult::Single(t) => Some(t.with_timezone(&Local)),
        _ => None,
    }
}

#[cfg(windows)]
mod windows_helper {
    use super::*;

    use std::os::windows::prelude::OsStrExt;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Storage::FileSystem::{
        FindFirstFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_REPARSE_POINT, WIN32_FIND_DATAW,
    };
    use windows::Win32::System::SystemServices::{
        IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
    };

    /// A secondary way to get file info on Windows, for when std::fs::symlink_metadata() fails.
    /// dir_entry_dict depends on metadata, but that can't be retrieved for some Windows system files:
    /// https://github.com/rust-lang/rust/issues/96980
    pub fn dir_entry_dict_windows_fallback(
        filename: &Path,
        display_name: &str,
        span: Span,
        long: bool,
    ) -> Value {
        let mut cols = vec![];
        let mut vals = vec![];

        cols.push("name".into());
        vals.push(Value::String {
            val: display_name.to_string(),
            span,
        });

        let find_data = match find_first_file(filename, span) {
            Ok(fd) => fd,
            Err(e) => {
                // Sometimes this happens when the file name is not allowed on Windows (ex: ends with a '.')
                // For now, we just log it and give up on returning metadata columns
                // TODO: find another way to get this data (like cmd.exe, pwsh, and MINGW bash can)
                eprintln!(
                    "Failed to read metadata for '{}'. It may have an illegal filename",
                    filename.to_string_lossy()
                );
                log::error!("{e}");
                return Value::Record { cols, vals, span };
            }
        };

        cols.push("type".into());
        vals.push(Value::String {
            val: get_file_type_windows_fallback(&find_data),
            span,
        });

        if long {
            cols.push("target".into());
            if is_symlink(&find_data) {
                if let Ok(path_to_link) = filename.read_link() {
                    vals.push(Value::String {
                        val: path_to_link.to_string_lossy().to_string(),
                        span,
                    });
                } else {
                    vals.push(Value::String {
                        val: "Could not obtain target file's path".to_string(),
                        span,
                    });
                }
            } else {
                vals.push(Value::nothing(span));
            }

            cols.push("readonly".into());
            vals.push(Value::Bool {
                val: (find_data.dwFileAttributes & FILE_ATTRIBUTE_READONLY.0 != 0),
                span,
            });
        }

        cols.push("size".to_string());
        let file_size = (find_data.nFileSizeHigh as u64) << 32 | find_data.nFileSizeLow as u64;
        vals.push(Value::Filesize {
            val: file_size as i64,
            span,
        });

        if long {
            cols.push("created".to_string());
            {
                let mut val = Value::nothing(span);
                let seconds_since_unix_epoch = unix_time_from_filetime(&find_data.ftCreationTime);
                if let Some(local) = unix_time_to_local_date_time(seconds_since_unix_epoch) {
                    val = Value::Date {
                        val: local.with_timezone(local.offset()),
                        span,
                    };
                }
                vals.push(val);
            }

            cols.push("accessed".to_string());
            {
                let mut val = Value::nothing(span);
                let seconds_since_unix_epoch = unix_time_from_filetime(&find_data.ftLastAccessTime);
                if let Some(local) = unix_time_to_local_date_time(seconds_since_unix_epoch) {
                    val = Value::Date {
                        val: local.with_timezone(local.offset()),
                        span,
                    };
                }
                vals.push(val);
            }
        }

        cols.push("modified".to_string());
        {
            let mut val = Value::nothing(span);
            let seconds_since_unix_epoch = unix_time_from_filetime(&find_data.ftLastWriteTime);
            if let Some(local) = unix_time_to_local_date_time(seconds_since_unix_epoch) {
                val = Value::Date {
                    val: local.with_timezone(local.offset()),
                    span,
                };
            }
            vals.push(val);
        }

        Value::Record { cols, vals, span }
    }

    fn unix_time_from_filetime(ft: &FILETIME) -> i64 {
        /// January 1, 1970 as Windows file time
        const EPOCH_AS_FILETIME: u64 = 116444736000000000;
        const HUNDREDS_OF_NANOSECONDS: u64 = 10000000;

        let time_u64 = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
        let rel_to_linux_epoch = time_u64 - EPOCH_AS_FILETIME;
        let seconds_since_unix_epoch = rel_to_linux_epoch / HUNDREDS_OF_NANOSECONDS;

        seconds_since_unix_epoch as i64
    }

    // wrapper around the FindFirstFileW Win32 API
    fn find_first_file(filename: &Path, span: Span) -> Result<WIN32_FIND_DATAW, ShellError> {
        unsafe {
            let mut find_data = WIN32_FIND_DATAW::default();
            // The windows crate really needs a nicer way to do string conversions
            let filename_wide: Vec<u16> = filename
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            match FindFirstFileW(
                windows::core::PCWSTR(filename_wide.as_ptr()),
                &mut find_data,
            ) {
                Ok(_) => Ok(find_data),
                Err(e) => {
                    return Err(ShellError::ReadingFile(
                        format!(
                            "Could not read metadata for '{}':\n  '{}'",
                            filename.to_string_lossy(),
                            e
                        ),
                        span,
                    ));
                }
            }
        }
    }

    fn get_file_type_windows_fallback(find_data: &WIN32_FIND_DATAW) -> String {
        if find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
            return "dir".to_string();
        }

        if is_symlink(find_data) {
            return "symlink".to_string();
        }

        "file".to_string()
    }

    fn is_symlink(find_data: &WIN32_FIND_DATAW) -> bool {
        if find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            // Follow Golang's lead in treating mount points as symlinks.
            // https://github.com/golang/go/blob/016d7552138077741a9c3fdadc73c0179f5d3ff7/src/os/types_windows.go#L104-L105
            if find_data.dwReserved0 == IO_REPARSE_TAG_SYMLINK
                || find_data.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT
            {
                return true;
            }
        }
        false
    }
}

fn get_prefix(
    pattern: &Spanned<String>,
    cwd: &Path,
) -> Result<(Option<PathBuf>, Vec<String>), ShellError> {
    let path = if pattern.item.starts_with("./") {
        &pattern.item[2..]
    } else {
        &pattern.item
    };
    let path = PathBuf::from(&path);
    let path = expand_path_with(path, cwd);
    let is_symlink = match fs::symlink_metadata(&path) {
        Ok(attr) => attr.file_type().is_symlink(),
        Err(_) => false,
    };

    let (prefix, the_pattern) = if path.to_string_lossy().contains('*') {
        // Path is a glob pattern => do not check for existence
        // Select the longest prefix until the first '*'
        let mut p = PathBuf::new();
        let mut len_to_star = 0;
        for c in path.components() {
            if let Component::Normal(os) = c {
                if os.to_string_lossy().contains('*') {
                    break;
                } else {
                    len_to_star += os.to_string_lossy().len() + 1; // + 1 for slash
                }
            }
            p.push(c);
        }
        #[cfg(target_os = "windows")]
        let pattern_after_star = &path.to_string_lossy().to_string()[(len_to_star + 3)..]; // +3 for c:\
        #[cfg(not(target_os = "windows"))]
        let pattern_after_star = &path.to_string_lossy().to_string()[(len_to_star)..];
        // eprintln!(
        //     "p: {:?}, len_to_star: {}, path: {}, pattern_after_start: {}",
        //     p,
        //     len_to_star,
        //     path.display(),
        //     pattern_after_star
        // );
        // let pattern_path = PathBuf::from(&pattern.item);
        // let pattern_path_clone = pattern_path.clone();
        // let pattern_without_prefix = match pattern_path.strip_prefix(p.clone()) {
        //     Ok(pat) => pat.to_path_buf(),
        //     Err(_) => pattern_path,
        // };
        // eprintln!(
        //     "pattern_path: {:?}, pattern_without_prefix: {:?}, p: {:?}",
        //     &pattern_path_clone, &pattern_without_prefix, &p
        // );
        let pattern_without_prefix = PathBuf::from(pattern_after_star);
        let patterns = pattern_without_prefix
            .display()
            .to_string()
            .split(", ")
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        (Some(p), patterns)
    } else if is_symlink {
        (
            path.parent().map(|parent| parent.to_path_buf()),
            path.display()
                .to_string()
                .split(", ")
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        )
    } else {
        let path = if let Ok(p) = canonicalize_with(path, cwd) {
            p
        } else {
            return Err(ShellError::DirectoryNotFound(pattern.span, None));
        };
        (
            path.parent().map(|parent| parent.to_path_buf()),
            path.display()
                .to_string()
                .split(", ")
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        )
    };
    Ok((prefix, the_pattern))
}
