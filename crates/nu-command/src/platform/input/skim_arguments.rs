use nu_engine::command_prelude::*;
use nu_protocol::{Value, engine::Closure};
use skim::binds::KeyMap;
use skim::prelude::{
    CaseMatching, DefaultSkimSelector, FuzzyAlgorithm, RankCriteria, Selector, SkimOptions,
};
use skim::tui::options::{PreviewLayout, TuiLayout};
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use crate::platform::input::skim_context::{
    CombinedSelector, CommandContext, NuCommandCollector, PredicateBasedSelector,
};

pub(crate) fn case_mode_from_flags(
    case_sensitive: bool,
    ignore_case: bool,
    smart_case: bool,
    head: Span,
) -> Result<CaseMatching, ShellError> {
    match (case_sensitive, ignore_case, smart_case) {
        (true, false, false) => Ok(CaseMatching::Respect),
        (false, true, false) => Ok(CaseMatching::Ignore),
        (false, false, true) => Ok(CaseMatching::Smart),
        (false, false, false) => Ok(CaseMatching::Smart),
        _ => Err(ShellError::IncorrectValue {
            msg: "Use only one of --case-sensitive, --ignore-case, or --smart-case.".into(),
            val_span: head,
            call_span: head,
        }),
    }
}

#[derive(Default, Debug)]
pub(crate) struct SkimDefaultOptions {
    pub bind: Vec<String>,
    pub prompt: Option<String>,
    pub cmd_prompt: Option<String>,
    pub multi: Option<bool>,
    pub tac: Option<bool>,
    pub no_sort: Option<bool>,
    pub tiebreak: Option<Vec<RankCriteria>>,
    pub exact: Option<bool>,
    pub interactive: Option<bool>,
    pub regex: Option<bool>,
    pub query: Option<String>,
    pub cmd_query: Option<String>,
    pub color: Option<String>,
    pub margin: Option<String>,
    pub no_height: Option<bool>,
    pub no_clear: Option<bool>,
    pub no_clear_start: Option<bool>,
    pub min_height: Option<String>,
    pub height: Option<String>,
    pub preview_window: Option<String>,
    pub reverse: Option<bool>,
    pub tabstop: Option<usize>,
    pub no_hscroll: Option<bool>,
    pub no_mouse: Option<bool>,
    pub inline_info: Option<bool>,
    pub layout: Option<String>,
    pub algorithm: Option<FuzzyAlgorithm>,
    pub case: Option<CaseMatching>,
    pub ansi: Option<bool>,
    pub keep_right: Option<bool>,
    pub skip_to_pattern: Option<String>,
    pub select1: Option<bool>,
    pub exit0: Option<bool>,
    pub sync: Option<bool>,
    pub no_clear_if_empty: Option<bool>,
    pub pre_select_n: Option<usize>,
    pub pre_select_pat: Option<String>,
    pub pre_select_items: Option<Vec<String>>,
    pub pre_select_file: Option<String>,
}

impl SkimDefaultOptions {
    pub(crate) fn from_env(engine_state: &EngineState, stack: &Stack) -> Self {
        let candidate = stack
            .get_env_var(engine_state, "SKIM_DEFAULT_OPTIONS")
            .or_else(|| stack.get_env_var(engine_state, "SKIM_DEFAULTS_OPTIONS"));

        candidate
            .and_then(|value| value.clone().coerce_string().ok())
            .and_then(|value| parse_skim_default_options(&value).ok())
            .unwrap_or_default()
    }
}

#[derive(Clone)]
pub(crate) struct SkimArguments {
    pub bind: Vec<String>,
    pub prompt: Option<String>,
    pub cmd_prompt: Option<String>,
    pub multi: bool,
    pub tac: bool,
    pub no_sort: bool,
    pub tiebreak: Vec<RankCriteria>,
    pub exact: bool,
    pub interactive: bool,
    pub query: Option<String>,
    pub cmd_query: Option<String>,
    pub color: Option<String>,
    pub margin: Option<String>,
    pub no_height: bool,
    pub no_clear: bool,
    pub no_clear_start: bool,
    pub min_height: Option<String>,
    pub height: Option<String>,
    pub preview_window: Option<String>,
    pub reverse: bool,
    pub ansi: bool,
    pub regex: bool,
    pub tabstop: Option<usize>,
    pub no_hscroll: bool,
    pub no_mouse: bool,
    pub inline_info: bool,
    pub layout: Option<TuiLayout>,
    pub algorithm: FuzzyAlgorithm,
    pub case: CaseMatching,
    pub keep_right: bool,
    pub skip_to_pattern: Option<String>,
    pub select1: bool,
    pub exit0: bool,
    pub sync: bool,
    pub no_clear_if_empty: bool,
    pub selector: Option<Rc<dyn Selector>>,
    pub cmd: Option<Spanned<Closure>>,
    pub format: Option<Spanned<Closure>>,
    pub preview: Option<Value>,
}

impl SkimArguments {
    pub(crate) fn new(
        call: &nu_protocol::engine::Call<'_>,
        engine_state: &EngineState,
        stack: &mut Stack,
    ) -> Result<Self, ShellError> {
        let defaults = SkimDefaultOptions::from_env(engine_state, stack);

        let bind =
            if let Some(bind_record) = call.get_flag::<Record>(engine_state, stack, "bind")? {
                bind_record
                    .into_iter()
                    .map(|(key, value)| {
                        let value = value.coerce_string()?;
                        Ok(format!("{key}:{value}"))
                    })
                    .collect::<Result<Vec<_>, ShellError>>()?
            } else {
                defaults.bind.clone()
            };

        let prompt: Option<String> = match call.opt(engine_state, stack, 0)? {
            Some(prompt) => Some(prompt),
            None => call
                .get_flag(engine_state, stack, "prompt")?
                .or_else(|| defaults.prompt.clone()),
        };

        let query: Option<String> = call
            .get_flag(engine_state, stack, "query")?
            .or_else(|| defaults.query.clone());

        let cmd_query: Option<String> = call
            .get_flag(engine_state, stack, "cmd-query")?
            .or_else(|| defaults.cmd_query.clone());

        let cmd_prompt: Option<String> = call
            .get_flag(engine_state, stack, "cmd-prompt")?
            .or_else(|| defaults.cmd_prompt.clone());

        let mut multi =
            call.has_flag(engine_state, stack, "multi")? || defaults.multi.unwrap_or(false);
        let tac = call.has_flag(engine_state, stack, "tac")? || defaults.tac.unwrap_or(false);
        let no_sort =
            call.has_flag(engine_state, stack, "no-sort")? || defaults.no_sort.unwrap_or(false);
        let exact = call.has_flag(engine_state, stack, "exact")? || defaults.exact.unwrap_or(false);
        let interactive = call.has_flag(engine_state, stack, "interactive")?
            || defaults.interactive.unwrap_or(false);
        let regex = call.has_flag(engine_state, stack, "regex")? || defaults.regex.unwrap_or(false);
        let no_height =
            call.has_flag(engine_state, stack, "no-height")? || defaults.no_height.unwrap_or(false);
        let no_clear =
            call.has_flag(engine_state, stack, "no-clear")? || defaults.no_clear.unwrap_or(false);
        let no_clear_start = call.has_flag(engine_state, stack, "no-clear-start")?
            || defaults.no_clear_start.unwrap_or(false);
        let reverse =
            call.has_flag(engine_state, stack, "reverse")? || defaults.reverse.unwrap_or(false);
        let no_hscroll = call.has_flag(engine_state, stack, "no-hscroll")?
            || defaults.no_hscroll.unwrap_or(false);
        let no_mouse =
            call.has_flag(engine_state, stack, "no-mouse")? || defaults.no_mouse.unwrap_or(false);
        let inline_info = call.has_flag(engine_state, stack, "inline-info")?
            || defaults.inline_info.unwrap_or(false);
        let keep_right = call.has_flag(engine_state, stack, "keep-right")?
            || defaults.keep_right.unwrap_or(false);
        let select1 =
            call.has_flag(engine_state, stack, "select-1")? || defaults.select1.unwrap_or(false);
        let exit0 =
            call.has_flag(engine_state, stack, "exit-0")? || defaults.exit0.unwrap_or(false);
        let sync = call.has_flag(engine_state, stack, "sync")? || defaults.sync.unwrap_or(false);
        let no_clear_if_empty = call.has_flag(engine_state, stack, "no-clear-if-empty")?
            || defaults.no_clear_if_empty.unwrap_or(false);

        let height: Option<String> = call
            .get_flag(engine_state, stack, "height")?
            .or_else(|| defaults.height.clone());

        let min_height: Option<String> = call
            .get_flag(engine_state, stack, "min-height")?
            .or_else(|| defaults.min_height.clone());

        let preview_window: Option<String> = call
            .get_flag(engine_state, stack, "preview-window")?
            .or_else(|| defaults.preview_window.clone());

        let color: Option<String> = call
            .get_flag(engine_state, stack, "color")?
            .or_else(|| defaults.color.clone());

        let margin: Option<String> = call
            .get_flag(engine_state, stack, "margin")?
            .or_else(|| defaults.margin.clone());

        let tabstop: Option<usize> = call
            .get_flag(engine_state, stack, "tabstop")?
            .or(defaults.tabstop);

        let layout = match call
            .get_flag(engine_state, stack, "layout")?
            .or(defaults.layout.clone())
        {
            Some(layout) => Some(match layout.to_lowercase().as_str() {
                "reverse" => TuiLayout::Reverse,
                "reverse-list" | "reverselist" => TuiLayout::ReverseList,
                "default" | "normal" | "" => TuiLayout::Default,
                other => {
                    return Err(ShellError::InvalidValue {
                        actual: other.to_owned(),
                        valid: "[default|reverse|reverse-list]".to_owned(),
                        span: call.head,
                    });
                }
            }),
            None => None,
        };

        let algorithm: FuzzyAlgorithm =
            match call.get_flag::<Spanned<String>>(engine_state, stack, "algo")? {
                Some(flag) => match flag.item.as_str() {
                    "skim_v1" | "skim_v2" => FuzzyAlgorithm::SkimV2,
                    "clangd" => FuzzyAlgorithm::Clangd,
                    "fzy" => FuzzyAlgorithm::Fzy,
                    "arinae" => FuzzyAlgorithm::Arinae,
                    "frizbee" => {
                        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                        {
                            FuzzyAlgorithm::Frizbee
                        }
                        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                        {
                            return Err(ShellError::InvalidValue {
                                actual: flag.item.clone(),
                                valid: "[skim_v1|skim_v2|clangd|fzy|arinae|frizbee]".to_owned(),
                                span: flag.span,
                            });
                        }
                    }
                    _ => {
                        return Err(ShellError::InvalidValue {
                            actual: flag.item.clone(),
                            valid: "[skim_v1|skim_v2|clangd|fzy|arinae|frizbee]".to_owned(),
                            span: flag.span,
                        });
                    }
                },
                None => defaults.algorithm.unwrap_or_default(),
            };

        let case = if call.has_flag(engine_state, stack, "case-sensitive")?
            || call.has_flag(engine_state, stack, "ignore-case")?
            || call.has_flag(engine_state, stack, "smart-case")?
        {
            case_mode_from_flags(
                call.has_flag(engine_state, stack, "case-sensitive")?,
                call.has_flag(engine_state, stack, "ignore-case")?,
                call.has_flag(engine_state, stack, "smart-case")?,
                call.head,
            )?
        } else if let Some(flag) = call.get_flag::<Spanned<String>>(engine_state, stack, "case")? {
            match flag.item.as_str() {
                "smart" => CaseMatching::Smart,
                "ignore" => CaseMatching::Ignore,
                "respect" => CaseMatching::Respect,
                _ => {
                    return Err(ShellError::InvalidValue {
                        actual: flag.item.clone(),
                        valid: "[smart|ignore|respect]".to_owned(),
                        span: flag.span,
                    });
                }
            }
        } else {
            defaults.case.unwrap_or(CaseMatching::Smart)
        };

        let tiebreak = if let Some(values) =
            call.get_flag::<Vec<Spanned<String>>>(engine_state, stack, "tiebreak")?
        {
            let parsed = values
                .into_iter()
                .map(|flag| {
                    parse_rank_criteria(&flag.item).ok_or(ShellError::InvalidValue {
                        actual: flag.item.clone(),
                        valid: "score/-score/begin/-begin/end/-end/length/-length/index/-index/pathname/-pathname".to_owned(),
                        span: flag.span,
                    })
                })
                .collect::<Result<Vec<_>, ShellError>>()?;
            if parsed.is_empty() {
                defaults.tiebreak.unwrap_or_default()
            } else {
                parsed
            }
        } else {
            defaults.tiebreak.unwrap_or_default()
        };

        let ansi = call.has_flag(engine_state, stack, "ansi")? || defaults.ansi.unwrap_or(false);

        let pre_select_n = call
            .get_flag(engine_state, stack, "pre-select-n")?
            .or(defaults.pre_select_n);
        let pre_select_pat = call
            .get_flag(engine_state, stack, "pre-select-pat")?
            .or(defaults.pre_select_pat.clone());
        let pre_select_items = call
            .get_flag(engine_state, stack, "pre-select-items")?
            .unwrap_or_else(|| defaults.pre_select_items.clone().unwrap_or_default());
        let pre_select_file = call
            .get_flag::<Spanned<String>>(engine_state, stack, "pre-select-file")?
            .map(|file| file.item)
            .or(defaults.pre_select_file.clone());
        let skip_to_pattern = call
            .get_flag(engine_state, stack, "skip-to-pattern")?
            .or(defaults.skip_to_pattern.clone());

        let mut selector: Option<Rc<dyn Selector>> = None;
        let mut dumb_selector: Option<DefaultSkimSelector> = None;

        if let Some(n) = defaults.pre_select_n {
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().first_n(n));
        }
        if let Some(pat) = defaults.pre_select_pat.clone() {
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().regex(&pat));
        }
        if !defaults
            .pre_select_items
            .clone()
            .unwrap_or_default()
            .is_empty()
        {
            dumb_selector = Some(
                dumb_selector
                    .take()
                    .unwrap_or_default()
                    .preset(defaults.pre_select_items.clone().unwrap_or_default()),
            );
        }
        if let Some(file_path) = defaults.pre_select_file.clone() {
            let items = read_preselect_file_items(engine_state, stack, &file_path, call.head)?;
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().preset(items));
        }

        if let Some(n) = call.get_flag(engine_state, stack, "pre-select-n")? {
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().first_n(n));
        }
        if let Some(pat) = call.get_flag::<String>(engine_state, stack, "pre-select-pat")? {
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().regex(&pat));
        }
        if let Some(items) =
            call.get_flag::<Vec<String>>(engine_state, stack, "pre-select-items")?
        {
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().preset(items));
        }
        if let Some(file_path) =
            call.get_flag::<Spanned<String>>(engine_state, stack, "pre-select-file")?
        {
            let items = read_preselect_file_items(engine_state, stack, &file_path.item, call.head)?;
            dumb_selector = Some(dumb_selector.take().unwrap_or_default().preset(items));
        }

        if let Some(predicate) =
            call.get_flag::<Spanned<Closure>>(engine_state, stack, "pre-select")?
        {
            let predicate_based_selector = PredicateBasedSelector {
                engine_state: engine_state.clone(),
                stack: Arc::new(stack.clone()),
                predicate,
            };
            selector = if let Some(dumb_selector) = dumb_selector {
                Some(Rc::new(CombinedSelector(
                    dumb_selector,
                    predicate_based_selector,
                )))
            } else {
                Some(Rc::new(predicate_based_selector))
            };
        } else if let Some(dumb_selector) = dumb_selector {
            selector = Some(Rc::new(dumb_selector));
        }

        let format = call.get_flag::<Spanned<Closure>>(engine_state, stack, "format")?;
        let preview = call.get_flag(engine_state, stack, "preview")?;
        let cmd = call.get_flag::<Spanned<Closure>>(engine_state, stack, "cmd")?;

        if pre_select_n.is_some()
            || pre_select_pat.is_some()
            || !pre_select_items.is_empty()
            || pre_select_file.is_some()
            || selector.is_some()
        {
            multi = true;
        }

        Ok(Self {
            bind,
            prompt,
            cmd_prompt,
            multi,
            tac,
            no_sort,
            tiebreak,
            exact,
            interactive,
            regex,
            query,
            cmd_query,
            color,
            margin,
            no_height,
            no_clear,
            no_clear_start,
            min_height,
            height,
            preview_window,
            reverse,
            tabstop,
            no_hscroll,
            no_mouse,
            inline_info,
            layout,
            algorithm,
            case,
            ansi,
            keep_right,
            skip_to_pattern,
            select1,
            exit0,
            sync,
            no_clear_if_empty,
            selector,
            cmd,
            format,
            preview,
        })
    }

    pub(crate) fn add_to_signature(signature: Signature) -> Signature {
        signature
            .named("bind", SyntaxShape::Record(Vec::new()), "Custom key bindings.", None)
            .switch("multi", "Select multiple values", Some('m'))
            .named("prompt", SyntaxShape::String, "Input prompt", None)
            .switch("tac", "Reverse the order of the search result (normally used with --no-sort)", None)
            .switch("no-sort", "Do not sort the search result (normally used together with --tac)", None)
            .named("tiebreak", SyntaxShape::List(Box::new(SyntaxShape::String)), "List of sort criteria to apply when the scores are tied.", None)
            .switch("exact", "Enable exact-match", Some('e'))
            .switch("interactive", "Start skim in interactive(command) mode", None)
            .named("query", SyntaxShape::String, "Specify the initial query", Some('q'))
            .named("cmd-query", SyntaxShape::String, "Specify the initial query for interactive mode", None)
            .named("cmd-prompt", SyntaxShape::String, "Command mode prompt", None)
            .switch("regex", "Search with regular expression instead of fuzzy match", None)
            .switch("ansi", "Enable ANSI color support for displayed items.", Some('a'))
            .switch("case-sensitive", "Match case-sensitively.", None)
            .switch("ignore-case", "Match case-insensitively.", None)
            .switch("smart-case", "Match case-insensitively unless uppercase is present.", None)
            .named("color", SyntaxShape::String, "Color configuration", None)
            .named("margin", SyntaxShape::String, "Comma-separated expression for margins around the finder.", None)
            .switch("no-height", "Disable height feature", None)
            .switch("no-clear", "Do not clear finder interface on exit", None)
            .switch("no-clear-start", "Do not clear on start", None)
            .named("height", SyntaxShape::String, "Display skim window with the given height instead of using the full screen", Some('H'))
            .named("min-height", SyntaxShape::String, "Minimum height when --height is given in percent. Ignored when --height is not specified", None)
            .named("preview-window", SyntaxShape::String, "Determines the layout of the preview window", None)
            .switch("reverse", "A synonym for --layout=reverse", None)
            .named("tabstop", SyntaxShape::Number, "Number of spaces for a tab character", None)
            .switch("no-hscroll", "Disable horizontal scroll", None)
            .switch("no-mouse", "Disable mouse", None)
            .switch("inline-info", "Display the finder info after the prompt with the default prefix ' < '", None)
            .named("layout", SyntaxShape::String, "Choose the layout", None)
            .named("algo", SyntaxShape::String, "Fuzzy matching algorithm: [skim_v1|skim_v2|clangd] (default: skim_v2)", None)
            .named("case", SyntaxShape::String, "Case sensitivity: [smart|ignore|respect] (default: smart)", None)
            .switch("keep-right", "Keep the right end of the line visible when it's too long", None)
            .named("skip-to-pattern", SyntaxShape::String, "Line will start with the start of the matched pattern", None)
            .switch("select-1", "Automatically select the only match", Some('1'))
            .switch("exit-0", "Exit immediately when there's no match", Some('0'))
            .switch("sync", "Wait for all the options to be available before choosing", None)
            .named("pre-select-n", SyntaxShape::Number, "Pre-select the first n items in multi-selection mode", None)
            .named("pre-select-pat", SyntaxShape::String, "Pre-select the matched items in multi-selection mode", None)
            .named("pre-select-items", SyntaxShape::List(Box::new(SyntaxShape::String)), "Pre-select the items in the given list", None)
            .named("pre-select-file", SyntaxShape::Filepath, "Pre-select the items read from file", None)
            .named("pre-select", SyntaxShape::Closure(Some(vec![])), "Pre-select the items that match the predicate", None)
            .switch("no-clear-if-empty", "Do not clear previous items if command returns empty result", None)
            .named("format", SyntaxShape::Closure(Some(vec![])), "Format each item for display.", Some('f'))
            .named(
                "preview",
                SyntaxShape::OneOf(vec![SyntaxShape::Closure(Some(vec![])), SyntaxShape::String]),
                "Preview expression or command; use $it or {} in closures to render preview content.",
                Some('p'),
            )
            .named("cmd", SyntaxShape::Closure(Some(vec![SyntaxShape::String])), "Command to invoke dynamically. A closure that receives the command query as its argument", Some('c'))
    }

    pub(crate) fn to_skim_options(
        &self,
        _head: Span,
        command_context: Option<Arc<CommandContext>>,
    ) -> Result<SkimOptions, ShellError> {
        let mut options = SkimOptions::default();
        let default_options = SkimOptions::default();

        options.bind = self.bind.clone();
        options.keymap = {
            let mut keymap = KeyMap::default();
            keymap.add_keymaps(self.bind.iter().map(String::as_str));
            keymap
        };
        options.multi = self.multi;
        options.no_multi = !self.multi;
        options.prompt = self.prompt.clone().unwrap_or_default();
        options.cmd_prompt = self.cmd_prompt.clone().unwrap_or_default();
        options.tac = self.tac;
        options.no_sort = self.no_sort;
        options.tiebreak = self.tiebreak.clone();
        options.exact = self.exact;
        options.cmd = if self.cmd.is_some() {
            Some("{q}".to_owned())
        } else {
            default_options.cmd
        };
        if let (Some(context), Some(cmd)) = (command_context, self.cmd.clone()) {
            options.cmd_collector = Rc::new(RefCell::new(NuCommandCollector {
                context,
                closure: cmd,
            }))
                as Rc<RefCell<dyn skim::reader::CommandCollector>>;
        }
        options.interactive = self.interactive;
        options.query = self.query.clone();
        options.cmd_query = self.cmd_query.clone();
        options.regex = self.regex;
        options.color = self.color.clone();
        options.margin = self.margin.clone().unwrap_or_else(|| "0,0,0,0".to_owned());
        options.no_height = self.no_height;
        options.no_clear = self.no_clear;
        options.no_clear_start = self.no_clear_start;
        options.min_height = self.min_height.clone().unwrap_or_else(|| "10".to_owned());
        options.height = self.height.clone().unwrap_or_else(|| "30%".to_owned());
        options.preview_window = self
            .preview_window
            .clone()
            .map(|value| PreviewLayout::from(value.as_str()))
            .unwrap_or_default();
        options.reverse = self.reverse;
        options.tabstop = self.tabstop.unwrap_or(8);
        options.no_hscroll = self.no_hscroll;
        options.no_mouse = self.no_mouse;
        options.inline_info = self.inline_info;
        options.layout = if self.reverse {
            TuiLayout::Reverse
        } else {
            self.layout.clone().unwrap_or_default()
        };
        options.algorithm = self.algorithm;
        options.case = self.case;
        options.keep_right = self.keep_right;
        options.skip_to_pattern = self.skip_to_pattern.clone();
        options.ansi = self.ansi;
        options.no_strip_ansi = self.ansi;
        options.select_1 = self.select1;
        options.exit_0 = self.exit0;
        // `--sync` can block indefinitely in non-interactive mode; only enable user-requested
        // sync for command mode features, but force it for `--select-1` so skim can
        // deterministically auto-accept a single match without opening the TUI.
        options.sync =
            self.select1 || self.exit0 || (self.sync && (self.interactive || self.cmd.is_some()));
        options.selector = self.selector.clone();
        options.no_clear_if_empty = self.no_clear_if_empty;
        options.preview = match &self.preview {
            Some(Value::String { val, .. }) => Some(val.clone()),
            Some(Value::Closure { .. }) => Some(String::new()),
            _ => default_options.preview,
        };
        // Do not set native pre_select_* fields — we already loaded all pre-selection
        // sources into `options.selector` above via our custom DefaultSkimSelector /
        // PredicateBasedSelector.  Setting both the native fields AND `selector` can
        // cause skim to create its own conflicting DefaultSkimSelector internally.
        options.shell = default_options.shell;
        options.nth = default_options.nth;
        options.delimiter = default_options.delimiter;
        options.read0 = default_options.read0;
        options.print0 = default_options.print0;
        options.print_query = default_options.print_query;
        options.print_cmd = default_options.print_cmd;
        options.print_score = default_options.print_score;
        options.filter = default_options.filter;
        options.cycle = default_options.cycle;
        options.border = default_options.border;
        options.normalize = default_options.normalize;
        options.split_match = default_options.split_match;
        options.disabled = default_options.disabled;
        options.selector_icon = default_options.selector_icon;
        options.multi_select_icon = default_options.multi_select_icon;
        options.wrap_items = default_options.wrap_items;
        options.print_header = default_options.print_header;
        options.shell_bindings = default_options.shell_bindings;
        options.man = default_options.man;
        options.listen = default_options.listen;
        options.remote = default_options.remote;
        options.log_file = default_options.log_file;

        Ok(options)
    }
}

pub(crate) fn parse_skim_default_options(s: &str) -> Result<SkimDefaultOptions, ()> {
    let mut options = SkimDefaultOptions::default();
    let mut tokens = shell_split(s).into_iter().peekable();

    while let Some(token) = tokens.next() {
        if token == "--" {
            break;
        }

        if let Some(rest) = token.strip_prefix("--") {
            let (key, value_opt) = if let Some(eq) = rest.find('=') {
                (rest[..eq].to_string(), Some(rest[eq + 1..].to_string()))
            } else {
                (rest.to_string(), None)
            };

            match key.as_str() {
                "bind" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.bind = split_csv_like(&value);
                    }
                }
                "multi" => options.multi = Some(true),
                "tac" => options.tac = Some(true),
                "no-sort" => options.no_sort = Some(true),
                "exact" => options.exact = Some(true),
                "interactive" => options.interactive = Some(true),
                "regex" => options.regex = Some(true),
                "no-height" => options.no_height = Some(true),
                "no-clear" => options.no_clear = Some(true),
                "no-clear-start" => options.no_clear_start = Some(true),
                "reverse" => options.reverse = Some(true),
                "no-hscroll" => options.no_hscroll = Some(true),
                "no-mouse" => options.no_mouse = Some(true),
                "inline-info" => options.inline_info = Some(true),
                "keep-right" => options.keep_right = Some(true),
                "select-1" => options.select1 = Some(true),
                "exit-0" => options.exit0 = Some(true),
                "sync" => options.sync = Some(true),
                "no-clear-if-empty" => options.no_clear_if_empty = Some(true),
                "ansi" => options.ansi = Some(true),
                "prompt" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.prompt = Some(value);
                    }
                }
                "cmd-prompt" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.cmd_prompt = Some(value);
                    }
                }
                "query" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.query = Some(value);
                    }
                }
                "cmd-query" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.cmd_query = Some(value);
                    }
                }
                "color" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.color = Some(value);
                    }
                }
                "margin" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.margin = Some(value);
                    }
                }
                "min-height" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.min_height = Some(value);
                    }
                }
                "height" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.height = Some(value);
                    }
                }
                "preview-window" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.preview_window = Some(value);
                    }
                }
                "layout" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.layout = Some(value);
                    }
                }
                "algo" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.algorithm = match value.as_str() {
                            "skim_v1" => Some(FuzzyAlgorithm::SkimV2),
                            "skim_v2" => Some(FuzzyAlgorithm::SkimV2),
                            "clangd" => Some(FuzzyAlgorithm::Clangd),
                            _ => None,
                        };
                    }
                }
                "case" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.case = match value.as_str() {
                            "smart" => Some(CaseMatching::Smart),
                            "ignore" => Some(CaseMatching::Ignore),
                            "respect" => Some(CaseMatching::Respect),
                            _ => None,
                        };
                    }
                }
                "skip-to-pattern" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.skip_to_pattern = Some(value);
                    }
                }
                "tabstop" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        if let Ok(n) = value.parse::<usize>() {
                            options.tabstop = Some(n);
                        }
                    }
                }
                "tiebreak" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        let vals = split_csv_like(&value);
                        let mut parsed = Vec::new();
                        for s in vals {
                            if let Some(rc) = parse_rank_criteria(&s) {
                                parsed.push(rc);
                            }
                        }
                        options.tiebreak = Some(parsed);
                    }
                }
                "pre-select-n" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        if let Ok(n) = value.parse::<usize>() {
                            options.pre_select_n = Some(n);
                        }
                    }
                }
                "pre-select-pat" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.pre_select_pat = Some(value);
                    }
                }
                "pre-select-items" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.pre_select_items = Some(split_csv_like(&value));
                    }
                }
                "pre-select-file" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.pre_select_file = Some(value);
                    }
                }
                _ => {}
            }
            continue;
        }

        if token.starts_with('-') {
            let mut chars = token[1..].chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    'm' => options.multi = Some(true),
                    'e' => options.exact = Some(true),
                    'i' => options.interactive = Some(true),
                    '1' => options.select1 = Some(true),
                    '0' => options.exit0 = Some(true),
                    'q' => {
                        let rest: String = chars.collect();
                        if !rest.is_empty() {
                            options.query = Some(rest);
                        } else if let Some(value) = tokens.next() {
                            options.query = Some(value);
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(options)
}

fn read_preselect_file_items(
    engine_state: &EngineState,
    stack: &Stack,
    file_path: &str,
    span: Span,
) -> Result<Vec<String>, ShellError> {
    let cwd = stack
        .get_env_var(engine_state, "PWD")
        .and_then(|value| value.coerce_string().ok())
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();

    let path = PathBuf::from(file_path);
    let resolved = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };

    let file = File::open(&resolved)
        .map_err(|err| ShellError::Io(IoError::new(err, span, resolved.clone())))?;
    BufReader::new(file)
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ShellError::Io(IoError::new(err, span, resolved)))
}

fn shell_split(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            '\'' | '"' => {
                if let Some(q) = quote {
                    if q == c {
                        quote = None;
                        continue;
                    }
                } else {
                    quote = Some(c);
                    continue;
                }
                current.push(c);
            }
            c if c.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    result.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

fn take_opt_value<I>(
    value_opt: Option<String>,
    tokens: &mut std::iter::Peekable<I>,
) -> Option<String>
where
    I: Iterator<Item = String>,
{
    if let Some(value) = value_opt {
        Some(value)
    } else {
        tokens.next()
    }
}

fn split_csv_like(s: &str) -> Vec<String> {
    s.split(&[',', ' '] as &[_])
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

fn parse_rank_criteria(value: &str) -> Option<RankCriteria> {
    match value.to_lowercase().as_str() {
        "score" => Some(RankCriteria::Score),
        "-score" => Some(RankCriteria::NegScore),
        "begin" => Some(RankCriteria::Begin),
        "-begin" => Some(RankCriteria::NegBegin),
        "end" => Some(RankCriteria::End),
        "-end" => Some(RankCriteria::NegEnd),
        "length" => Some(RankCriteria::Length),
        "-length" => Some(RankCriteria::NegLength),
        "index" => Some(RankCriteria::Index),
        "-index" => Some(RankCriteria::NegIndex),
        "pathname" => Some(RankCriteria::PathName),
        "-pathname" => Some(RankCriteria::NegPathName),
        _ => None,
    }
}
