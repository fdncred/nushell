use nu_color_config::StyleComputer;
use nu_engine::{ClosureEval, command_prelude::*, eval_call};
use nu_protocol::{
    Config, Value,
    ast::Call as AstCall,
    debugger::{WithDebug, WithoutDebug},
    engine::Closure,
};
use nu_table::common::{nu_value_to_string_clean, nu_value_to_string_colored};
use ratatui::text::Line;
use skim::binds::KeyMap;
use skim::prelude::{
    CaseMatching, Cow, DefaultSkimSelector, DisplayContext, FuzzyAlgorithm, ItemPreview,
    PreviewContext, RankCriteria, Selector, Sender, Skim, SkimItem, SkimItemReceiver, SkimOptions,
    unbounded,
};
use skim::reader::CommandCollector;
use skim::tui::options::{PreviewLayout, TuiLayout};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;

fn case_mode_from_flags(
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
struct SkimDefaultOptions {
    bind: Vec<String>,
    prompt: Option<String>,
    cmd_prompt: Option<String>,
    multi: Option<bool>,
    tac: Option<bool>,
    no_sort: Option<bool>,
    tiebreak: Option<Vec<RankCriteria>>,
    exact: Option<bool>,
    interactive: Option<bool>,
    query: Option<String>,
    cmd_query: Option<String>,
    regex: Option<bool>,
    color: Option<String>,
    margin: Option<String>,
    no_height: Option<bool>,
    no_clear: Option<bool>,
    no_clear_start: Option<bool>,
    min_height: Option<String>,
    height: Option<String>,
    preview_window: Option<String>,
    reverse: Option<bool>,
    tabstop: Option<usize>,
    no_hscroll: Option<bool>,
    no_mouse: Option<bool>,
    inline_info: Option<bool>,
    layout: Option<String>,
    algorithm: Option<FuzzyAlgorithm>,
    case: Option<CaseMatching>,
    ansi: Option<bool>,
    keep_right: Option<bool>,
    skip_to_pattern: Option<String>,
    select1: Option<bool>,
    exit0: Option<bool>,
    sync: Option<bool>,
    no_clear_if_empty: Option<bool>,
    pre_select_n: Option<usize>,
    pre_select_pat: Option<String>,
    pre_select_items: Option<Vec<String>>,
    pre_select_file: Option<String>,
}

impl SkimDefaultOptions {
    fn from_env(engine_state: &EngineState, stack: &Stack) -> Self {
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
struct SkimArguments {
    bind: Vec<String>,
    prompt: Option<String>,
    cmd_prompt: Option<String>,
    multi: bool,
    tac: bool,
    no_sort: bool,
    tiebreak: Vec<RankCriteria>,
    exact: bool,
    interactive: bool,
    query: Option<String>,
    cmd_query: Option<String>,
    regex: bool,
    color: Option<String>,
    margin: Option<String>,
    no_height: bool,
    no_clear: bool,
    no_clear_start: bool,
    min_height: Option<String>,
    height: Option<String>,
    preview_window: Option<String>,
    reverse: bool,
    ansi: bool,
    tabstop: Option<usize>,
    no_hscroll: bool,
    no_mouse: bool,
    inline_info: bool,
    layout: Option<TuiLayout>,
    algorithm: FuzzyAlgorithm,
    case: CaseMatching,
    keep_right: bool,
    skip_to_pattern: Option<String>,
    select1: bool,
    exit0: bool,
    sync: bool,
    no_clear_if_empty: bool,
    pre_select_n: Option<usize>,
    pre_select_pat: Option<String>,
    pre_select_items: Vec<String>,
    pre_select_file: Option<String>,
    selector: Option<Rc<dyn Selector>>,
    cmd: Option<Spanned<Closure>>,
    format: Option<Spanned<Closure>>,
    preview: Option<Value>,
}

impl SkimArguments {
    fn new(
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

        let multi = call.has_flag(engine_state, stack, "multi")? || defaults.multi.unwrap_or(false);
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

        let case = case;
        let layout = layout;

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
            if let Ok(file) = File::open(file_path.clone()) {
                if let Ok(items) = BufReader::new(file).lines().collect::<Result<Vec<_>, _>>() {
                    dumb_selector = Some(dumb_selector.take().unwrap_or_default().preset(items));
                }
            }
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
            if let Ok(file) = File::open(file_path.item.clone()) {
                if let Ok(items) = BufReader::new(file).lines().collect::<Result<Vec<_>, _>>() {
                    dumb_selector = Some(dumb_selector.take().unwrap_or_default().preset(items));
                }
            }
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
            query,
            cmd_query,
            regex,
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
            pre_select_n,
            pre_select_pat,
            pre_select_items,
            pre_select_file,
            selector,
            cmd,
            format,
            preview,
        })
    }

    fn add_to_signature(signature: Signature) -> Signature {
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
            .named("min-height", SyntaxShape::Number, "Minimum height when --height is given in percent. Ignored when --height is not specified", None)
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

    fn to_skim_options(
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
            })) as Rc<RefCell<dyn CommandCollector>>;
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
        options.select_1 = self.select1;
        options.exit_0 = self.exit0;
        options.sync = self.sync;
        options.selector = self.selector.clone();
        options.no_clear_if_empty = self.no_clear_if_empty;
        options.preview = match &self.preview {
            Some(Value::String { val, .. }) => Some(val.clone()),
            Some(Value::Closure { .. }) => Some(String::new()),
            _ => default_options.preview,
        };
        options.pre_select_n = self.pre_select_n.unwrap_or_default();
        options.pre_select_pat = self.pre_select_pat.clone().unwrap_or_default();
        options.pre_select_items = self.pre_select_items.join("\n");
        options.pre_select_file = self.pre_select_file.clone();
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
        options.no_strip_ansi = default_options.no_strip_ansi;
        options.shell_bindings = default_options.shell_bindings;
        options.man = default_options.man;
        options.listen = default_options.listen;
        options.remote = default_options.remote;
        options.log_file = default_options.log_file;

        Ok(options)
    }
}

pub struct CommandContext {
    pub engine_state: EngineState,
    pub stack: Arc<Stack>,
    pub nu_config: Arc<Config>,
    pub format: MapperFlag,
    pub preview: MapperFlag,
}

impl CommandContext {
    fn new(engine_state: &EngineState, stack: &Stack) -> Result<Self, ShellError> {
        Ok(Self {
            engine_state: engine_state.clone(),
            stack: Arc::new(stack.clone()),
            nu_config: stack.get_config(engine_state),
            format: MapperFlag::None,
            preview: MapperFlag::None,
        })
    }
}

pub enum MapperFlag {
    None,
    Closure(Spanned<Closure>),
}

impl TryFrom<Value> for MapperFlag {
    type Error = ShellError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Closure { ref val, .. } => Ok(Self::Closure(
                val.as_ref().clone().into_spanned(value.span()),
            )),
            _ => Err(ShellError::CantConvert {
                to_type: "closure".to_owned(),
                from_type: value.get_type().to_string(),
                span: value.span(),
                help: None,
            }),
        }
    }
}

impl MapperFlag {
    fn map<'a>(&self, context: &CommandContext, value: &'a Value) -> Cow<'a, Value> {
        match self {
            MapperFlag::None => Cow::Borrowed(value),
            MapperFlag::Closure(closure) => {
                let mut stack = (*context.stack).clone();
                let mut eval =
                    ClosureEval::new(&context.engine_state, &mut stack, closure.item.clone());
                match eval.run_with_value(value.clone()) {
                    Ok(PipelineData::Empty) => Cow::Owned(Value::nothing(closure.span)),
                    Ok(PipelineData::Value(value, _)) => Cow::Owned(value),
                    Ok(PipelineData::ListStream(list_stream, _)) => {
                        let span = list_stream.span();
                        Cow::Owned(
                            list_stream
                                .into_value()
                                .unwrap_or_else(|err| Value::error(err, span)),
                        )
                    }
                    Ok(PipelineData::ByteStream(byte_stream, _)) => {
                        let span = byte_stream.span();
                        Cow::Owned(match byte_stream.into_string() {
                            Ok(text) => Value::string(text, span),
                            Err(err) => Value::error(err, span),
                        })
                    }
                    Err(err) => Cow::Owned(Value::error(err, closure.span)),
                }
            }
        }
    }
}

pub struct NuItem {
    pub context: Arc<CommandContext>,
    pub value: Value,
    pub display: Line<'static>,
}

impl NuItem {
    pub fn new(context: Arc<CommandContext>, value: Value) -> Self {
        let display = Line::from(
            context
                .format
                .map(&context, &value)
                .to_expanded_string(", ", &context.nu_config),
        );

        Self {
            context,
            value,
            display,
        }
    }
}

impl SkimItem for NuItem {
    fn text(&self) -> Cow<'_, str> {
        self.display.to_string().into()
    }

    fn display<'a>(&'a self, _context: DisplayContext) -> Line<'a> {
        self.display.clone()
    }

    fn preview(&self, _context: PreviewContext<'_>) -> ItemPreview {
        let preview_result = self.context.preview.map(&self.context, &self.value);
        if let Ok(preview_string) = preview_result.clone().coerce_string() {
            return ItemPreview::AnsiText(preview_string);
        }

        let result = self
            .context
            .engine_state
            .find_decl("table".as_bytes(), &[])
            .and_then(|table_decl_id| {
                let table_call = AstCall {
                    decl_id: table_decl_id,
                    head: self.value.span(),
                    arguments: Vec::new(),
                    parser_info: HashMap::new(),
                };
                let mut stack = (*self.context.stack).clone();
                let output = if self.context.engine_state.is_debugging() {
                    eval_call::<WithDebug>(
                        &self.context.engine_state,
                        &mut stack,
                        &table_call,
                        PipelineData::Value(self.value.clone(), None),
                    )
                } else {
                    eval_call::<WithoutDebug>(
                        &self.context.engine_state,
                        &mut stack,
                        &table_call,
                        PipelineData::Value(self.value.clone(), None),
                    )
                };
                match output {
                    Ok(table_output) => table_output
                        .collect_string("\n", &self.context.nu_config)
                        .ok(),
                    Err(_) => None,
                }
            })
            .unwrap_or_default();

        ItemPreview::AnsiText(result)
    }
}

struct PredicateBasedSelector {
    pub engine_state: EngineState,
    pub stack: Arc<Stack>,
    pub predicate: Spanned<Closure>,
}

impl Selector for PredicateBasedSelector {
    fn should_select(&self, _index: usize, item: &dyn SkimItem) -> bool {
        let Some(nu_item) = item.as_any().downcast_ref::<NuItem>() else {
            return false;
        };

        let mut stack = (*self.stack).clone();
        let mut eval =
            ClosureEval::new(&self.engine_state, &mut stack, self.predicate.item.clone());
        let result = eval.run_with_value(nu_item.value.clone());
        let result = match result {
            Ok(PipelineData::Value(value, _)) => value.is_true(),
            _ => false,
        };
        result
    }
}

struct CombinedSelector(pub DefaultSkimSelector, pub PredicateBasedSelector);

impl Selector for CombinedSelector {
    fn should_select(&self, index: usize, item: &dyn SkimItem) -> bool {
        self.0.should_select(index, item) || self.1.should_select(index, item)
    }
}

struct NuCommandCollector {
    context: Arc<CommandContext>,
    closure: Spanned<Closure>,
}

impl CommandCollector for NuCommandCollector {
    fn invoke(
        &mut self,
        cmd: &str,
        components_to_stop: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> (SkimItemReceiver, Sender<i32>) {
        let (tx, rx) = unbounded::<Vec<Arc<dyn SkimItem>>>();
        let (tx_interrupt, rx_interrupt) = unbounded::<i32>();
        let context = self.context.clone();
        let closure = self.closure.clone();
        let cmd = cmd.to_owned();

        thread::spawn(move || {
            components_to_stop.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stack = (*context.stack).clone();
            let mut eval =
                ClosureEval::new(&context.engine_state, &mut stack, closure.item.clone());
            let output = eval.run_with_value(Value::string(cmd, closure.span));

            match output {
                Ok(PipelineData::ByteStream(stream, _)) => {
                    let span = stream.span();
                    if let Some(lines) = stream.lines() {
                        for (_index, line) in lines.enumerate() {
                            if rx_interrupt.try_recv().is_ok() {
                                break;
                            }
                            let items = match line {
                                Ok(text) => vec![Arc::new(NuItem::new(
                                    context.clone(),
                                    Value::string(text, span),
                                ))
                                    as Arc<dyn SkimItem>],
                                Err(err) => vec![Arc::new(NuItem::new(
                                    context.clone(),
                                    Value::error(err, span),
                                ))
                                    as Arc<dyn SkimItem>],
                            };
                            if tx.send(items).is_err() {
                                break;
                            }
                        }
                    }
                }
                Ok(output) => {
                    let values: Vec<Value> = output.into_iter().collect();
                    for value in values.into_iter() {
                        if rx_interrupt.try_recv().is_ok() {
                            break;
                        }
                        let item =
                            Arc::new(NuItem::new(context.clone(), value)) as Arc<dyn SkimItem>;
                        if tx.send(vec![item]).is_err() {
                            break;
                        }
                    }
                }
                Err(err) => {
                    let _ = tx.send(vec![Arc::new(NuItem::new(
                        context.clone(),
                        Value::error(err, closure.span),
                    )) as Arc<dyn SkimItem>]);
                }
            }

            components_to_stop.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });

        (rx, tx_interrupt)
    }
}

fn parse_skim_default_options(s: &str) -> Result<SkimDefaultOptions, ()> {
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
                    'm' => options.tac = Some(true),
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

fn format_skim_item(
    value: &Value,
    config: &Config,
    style_computer: &StyleComputer,
    ansi: bool,
) -> (String, String) {
    let (plain_text, _) = nu_value_to_string_clean(value, config, style_computer);
    if ansi {
        let display = nu_value_to_string_colored(value, config, style_computer);
        (display, plain_text)
    } else {
        (plain_text.clone(), plain_text)
    }
}

fn format_skim_item_with_closure(
    value: &Value,
    config: &Config,
    style_computer: &StyleComputer,
    ansi: bool,
    format: &mut Option<ClosureEval>,
) -> Result<(String, String), ShellError> {
    if let Some(format) = format {
        let formatted = format
            .run_with_value(value.clone())?
            .collect_string(" ", config)?;
        if formatted.is_empty() {
            Ok(format_skim_item(value, config, style_computer, ansi))
        } else {
            Ok((formatted.clone(), formatted))
        }
    } else {
        Ok(format_skim_item(value, config, style_computer, ansi))
    }
}

fn preview_skim_item_with_closure(
    value: &Value,
    config: &Config,
    style_computer: &StyleComputer,
    ansi: bool,
    engine_state: &EngineState,
    stack: &mut Stack,
    preview: &mut Option<ClosureEval>,
) -> Result<Option<String>, ShellError> {
    if let Some(preview) = preview {
        let preview_data = preview.run_with_value(value.clone())?;
        let preview_value = preview_data.into_value(value.span())?;

        if let Ok(preview_string) = preview_value.clone().coerce_string() {
            if !preview_string.is_empty() {
                return Ok(Some(preview_string));
            }
        }

        if let Some(table_decl_id) = engine_state.find_decl("table".as_bytes(), &[]) {
            let table_call = AstCall {
                decl_id: table_decl_id,
                head: value.span(),
                arguments: Vec::new(),
                parser_info: HashMap::new(),
            };

            let table_output = if engine_state.is_debugging() {
                eval_call::<WithDebug>(
                    engine_state,
                    stack,
                    &table_call,
                    PipelineData::Value(preview_value.clone(), None),
                )
            } else {
                eval_call::<WithoutDebug>(
                    engine_state,
                    stack,
                    &table_call,
                    PipelineData::Value(preview_value.clone(), None),
                )
            }?;

            let table_text = table_output.collect_string("\n", config)?;
            if !table_text.is_empty() {
                return Ok(Some(table_text));
            }
        }

        let preview_text = if let Ok(preview_string) = preview_value.clone().coerce_string() {
            preview_string
        } else {
            let (display, _) = format_skim_item(&preview_value, config, style_computer, ansi);
            display
        };

        if preview_text.is_empty() {
            let (_display, text) = format_skim_item(value, config, style_computer, ansi);
            Ok(Some(text))
        } else {
            Ok(Some(preview_text))
        }
    } else {
        Ok(None)
    }
}

#[derive(Clone)]
pub struct SkimValueItem {
    display: String,
    text: String,
    preview: Option<String>,
    index: usize,
}

impl SkimItem for SkimValueItem {
    fn text(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.text.as_str())
    }

    fn display(&self, context: DisplayContext) -> Line<'_> {
        context.to_line(Cow::Borrowed(self.display.as_str()))
    }

    fn preview(&self, _context: PreviewContext<'_>) -> ItemPreview {
        match &self.preview {
            Some(preview) => ItemPreview::AnsiText(preview.clone()),
            None => ItemPreview::Global,
        }
    }

    fn output(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.text.as_str())
    }
}

#[derive(Clone)]
pub struct SkimCommand;

impl Command for SkimCommand {
    fn name(&self) -> &str {
        "skim"
    }

    fn signature(&self) -> Signature {
        SkimArguments::add_to_signature(Signature::build("skim"))
            .optional(
                "prompt",
                SyntaxShape::String,
                "Prompt shown before the search box.",
            )
            .switch(
                "index",
                "Return the selected item index or indexes instead of values.",
                Some('i'),
            )
            .category(Category::Platform)
    }

    fn description(&self) -> &str {
        "Run an interactive skim selection."
    }

    fn extra_description(&self) -> &str {
        r#"This command uses the skim library directly to preserve selected Nu values.
Use --multi for multiple selection, --format to format items for display, --preview to render preview content with a closure, and --index to return item indexes.

Key bindings:
  Enter         Accept current item and quit
  Esc / Ctrl-G  Abort
  Ctrl-P / Up   Move cursor up
  Ctrl-N / Down Move cursor down
  Tab           Toggle selection and move down (with --multi)
  Shift-Tab     Toggle selection and move up (with --multi)

Search syntax:
  text      fuzzy-match
  ^prefix   prefix-exact-match
  .suffix$  suffix-exact-match
  'quoted   exact-match
  !term     inverse-exact-match
  !.suffix$ inverse-suffix-exact-match

Whitespace means AND, ` | ` means OR, and OR has higher precedence.
Use --regex or Ctrl-R to switch into regex mode."#
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["sk", "fzf", "pick", "choose", "filter", "interactive"]
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &nu_protocol::engine::Call<'_>,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let head = call.head;
        let skim_args = SkimArguments::new(call, engine_state, stack)?;
        let mut command_context = CommandContext::new(engine_state, stack)?;
        if let Some(format) = skim_args.format.clone() {
            command_context.format = MapperFlag::Closure(format);
        }
        if let Some(Value::Closure {
            val, internal_span, ..
        }) = skim_args.preview.clone()
        {
            command_context.preview =
                MapperFlag::Closure(val.as_ref().clone().into_spanned(internal_span));
        }
        let command_context = Arc::new(command_context);
        let options = skim_args.to_skim_options(head, Some(command_context.clone()))?;
        let index_flag = call.has_flag(engine_state, stack, "index")?;
        let multi = skim_args.multi;

        let config = stack.get_config(engine_state);
        let stack_for_style = stack.clone();
        let style_computer = StyleComputer::from_config(engine_state, &stack_for_style);
        let mut preview_stack = stack.clone();

        let mut format_closure = skim_args
            .format
            .clone()
            .map(|closure| ClosureEval::new(engine_state, stack, closure.item.clone()));
        let mut preview_closure = match skim_args.preview.clone() {
            Some(Value::Closure { val, .. }) => Some(ClosureEval::new(engine_state, stack, *val)),
            _ => None,
        };

        let (skim_output, values) = match input {
            PipelineData::ListStream(..) => {
                let (tx, rx) = unbounded();

                let mut values = Vec::new();
                let mut batch: Vec<Arc<dyn SkimItem>> = Vec::with_capacity(1024);

                for (idx, value) in input.into_iter().enumerate() {
                    let (display, text) = format_skim_item_with_closure(
                        &value,
                        &config,
                        &style_computer,
                        skim_args.ansi,
                        &mut format_closure,
                    )?;
                    let preview = preview_skim_item_with_closure(
                        &value,
                        &config,
                        &style_computer,
                        skim_args.ansi,
                        engine_state,
                        &mut preview_stack,
                        &mut preview_closure,
                    )?;

                    values.push(value.clone());
                    batch.push(Arc::new(SkimValueItem {
                        display,
                        text,
                        preview,
                        index: idx,
                    }));

                    if batch.len() == 1024 {
                        let batch_to_send = std::mem::take(&mut batch);
                        if tx.send(batch_to_send).is_err() {
                            break;
                        }
                        batch = Vec::with_capacity(1024);
                    }
                }

                if !batch.is_empty() {
                    let _ = tx.send(batch);
                }
                drop(tx);

                let skim_output = Skim::run_with(options, Some(rx)).map_err(|err| {
                    ShellError::ExternalCommand {
                        label: "Failed to run skim".into(),
                        help: err.to_string(),
                        span: head,
                    }
                })?;

                (skim_output, values)
            }
            PipelineData::Value(Value::List { .. }, ..)
            | PipelineData::Value(Value::Range { .. }, ..) => {
                let values: Vec<Value> = input.into_iter().collect();

                if values.is_empty() {
                    return Err(ShellError::TypeMismatch {
                        err_message: "expected a list or range with at least one item".to_string(),
                        span: head,
                    });
                }

                let items = values
                    .iter()
                    .enumerate()
                    .map(|(idx, value)| {
                        let (display, text) = format_skim_item_with_closure(
                            value,
                            &config,
                            &style_computer,
                            skim_args.ansi,
                            &mut format_closure,
                        )?;
                        let preview = preview_skim_item_with_closure(
                            value,
                            &config,
                            &style_computer,
                            skim_args.ansi,
                            engine_state,
                            &mut preview_stack,
                            &mut preview_closure,
                        )?;
                        Ok(SkimValueItem {
                            display,
                            text,
                            preview,
                            index: idx,
                        })
                    })
                    .collect::<Result<Vec<_>, ShellError>>()?;

                let skim_output =
                    Skim::run_items(options, items).map_err(|err| ShellError::ExternalCommand {
                        label: "Failed to run skim".into(),
                        help: err.to_string(),
                        span: head,
                    })?;

                (skim_output, values)
            }
            _ => {
                return Err(ShellError::TypeMismatch {
                    err_message: "expected a list or range".to_string(),
                    span: head,
                });
            }
        };
        if skim_output.is_abort {
            return Ok(Value::nothing(head).into_pipeline_data());
        }

        let selected_indexes = skim_output
            .selected_items
            .iter()
            .filter_map(|item| {
                item.as_any()
                    .downcast_ref::<SkimValueItem>()
                    .map(|item| item.index)
                    .or_else(|| item.output().parse::<usize>().ok())
            })
            .collect::<Vec<usize>>();

        if selected_indexes.iter().any(|&idx| idx >= values.len()) {
            return Err(ShellError::ExternalCommand {
                label: "skim returned an out-of-range selection".into(),
                help: "Selected item index exceeded the number of available items.".into(),
                span: head,
            });
        }

        let result = if index_flag {
            if multi {
                Value::list(
                    selected_indexes
                        .into_iter()
                        .map(|idx| Value::int(idx as i64, head))
                        .collect(),
                    head,
                )
            } else if let Some(idx) = selected_indexes.into_iter().next() {
                Value::int(idx as i64, head)
            } else {
                Value::nothing(head)
            }
        } else if multi {
            Value::list(
                selected_indexes
                    .into_iter()
                    .map(|idx| values[idx].clone())
                    .collect(),
                head,
            )
        } else if let Some(idx) = selected_indexes.into_iter().next() {
            values[idx].clone()
        } else {
            Value::nothing(head)
        };

        Ok(result.into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example { // working
                description: "Show a custom prompt before the search box.",
                example: "[1 2 3 4 5] | skim 'Choose one'",
                result: None,
            },
            Example { // working
                description: "Show a custom prompt using the named prompt flag.",
                example: "[one two three] | skim --prompt 'Pick one'",
                result: None,
            },
            Example { // working
                description: "Use a custom key binding.",
                example: "[Foo Bar] | skim --bind {'ctrl-j':'down'} 'Select item'",
                result: None,
            },
            Example { // working
                description: "Allow selecting multiple items and preserve order.",
                example: "[Banana Kiwi Pear] | skim --multi --tac --no-sort 'Select fruit'",
                result: None,
            },
            Example { // NOT-working shows 39m instead of a color
                description: "Enable ANSI color support for displayed items.",
                example: "[\"apple\" \"banana\"] | skim --ansi --query apple",
                result: None,
            },
            Example { // working
                description: "Search with regular expressions.",
                example: "[foo bar baz] | skim --regex 'regex> '",
                result: None,
            },
            Example { // NOT-working. should work with `rg --files | skim --tiebreak [score length]`
                description: "Use sort tiebreak criteria.",
                example: "[foo bar baz] | skim --tiebreak [score length] 'a'",
                result: None,
            },
            Example { // NOT-working, maybe - not sure what it's supposed to do
                description: "Set a color theme and window margin.",
                example: "[one two] | skim --color 'fg:blue' --margin '1,2,1,2' 'Choose'",
                result: None,
            },
            Example { // NOT-working, syntax error
                description: "Disable and configure window height.",
                example: "[one two three] | skim --no-height --height 30% --min-height 10 'Small'",
                result: None,
            },
            Example { // working
                description: "Disable screen clearing on start and exit.",
                example: "[one two] | skim --no-clear-start --no-clear --no-clear-if-empty 'Keep visible'",
                result: None,
            },
            Example { // working
                description: "Use reverse layout and keep the right side visible.",
                example: "[long-line another] | skim --reverse --layout reverse --keep-right 'Navigate'",
                result: None,
            },
            Example { // working
                description: "Control tab width and input behavior.",
                example: "[\"one\ttwo\"] | skim --tabstop 4 --no-hscroll --no-mouse --inline-info 'Show'",
                result: None,
            },
            Example { // working
                description: "Use a different fuzzy matching algorithm and case mode.",
                example: "[foo bar] | skim --algo clangd --case ignore 'prompt> '",
                result: None,
            },
            Example { // working
                description: "Enable exact matching instead of fuzzy match.",
                example: "[foo bar] | skim --exact 'prompt> '",
                result: None,
            },
            Example { // working
                description: "Match case sensitively.",
                example: "[Foo foo] | skim --case-sensitive 'prompt> '",
                result: None,
            },
            Example { // working
                description: "Match case insensitively.",
                example: "[Foo foo] | skim --ignore-case 'prompt> '",
                result: None,
            },
            Example { // working
                description: "Use smart case matching.",
                example: "[Foo foo] | skim --smart-case 'prompt> '",
                result: None,
            },
            Example { // working
                description: "Use a preview window layout.",
                example: "[one two] | skim --preview-window right:50% --preview {||} 'prompt> '",
                result: None,
            },
            Example { // NOT-working, doesn't seem to be reading the file
                description: "Pre-select items read from a file.",
                example: "[one two] | skim --pre-select-file preselect.txt",
                result: None,
            },
            Example { // working
                description: "Skip to the matched pattern in each line.",
                example: "[a:1 b:2] | skim --skip-to-pattern ':' 'prompt> '",
                result: None,
            },
            Example { // NOT-working, hangs the ui
                description: "Select only one match without opening skim.",
                example: "[one] | skim --select-1",
                result: Some(Value::test_string("one")),
            },
            Example { // working
                description: "Exit with code 0 if there is no match.",
                example: "[one] | skim --exit-0 'prompt> '",
                result: Some(Value::nothing(Span::test_data())),
            },
            Example { // NOT-working, hangs the ui
                description: "Wait for input to finish before showing results.",
                example: "[one two three] | skim --sync 'Sync search'",
                result: None,
            },
            Example { // no clue what this is supposed to do
                description: "Pre-select items by index, pattern, or list.",
                example: "[one two three] | skim --pre-select-n 1 --pre-select-pat 't' --pre-select-items ['one'] 'Choose'",
                result: None,
            },
            Example { // NOT-working
                description: "Use a predicate to pre-select matching items.",
                example: "[one two three] | skim --pre-select { || $in == 'one' }",
                result: None,
            },
            Example { // working
                description: "Format and preview values while selecting.",
                example: "ps | skim --format {get name} --preview {||}",
                result: None,
            },
            Example { // NOT-working. doesn't seem to stream but maybe it's all the other parms making it wait
                description: "Use interactive mode with command mode prompt and query.",
                example: "glob **/*.rs | skim --interactive --cmd-query test --cmd-prompt 'cmd> ' --cmd { |q| echo $q }",
                result: None,
            },
            Example { // working
                description: "Return the selected item index instead of the value.",
                example: "[Banana Kiwi Pear] | skim --index",
                result: None,
            },
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nu_protocol::{Example, Span, Value};
    use std::collections::HashSet;

    fn is_single_item_input(example: &str) -> bool {
        let example = example.trim();
        if let Some(pipe_pos) = example.find("| skim") {
            let input = example[..pipe_pos].trim();
            if input.starts_with('[') && input.ends_with(']') {
                let inner = input[1..input.len() - 1].trim();
                if inner.is_empty() {
                    return false;
                }
                if inner.starts_with('"') && inner.ends_with('"') {
                    return !inner[1..inner.len() - 1].contains('"');
                }
                !inner.contains(' ')
            } else {
                false
            }
        } else {
            false
        }
    }

    fn is_headless_example(example: &str) -> bool {
        if example.contains("--exit-0") && example.contains("--query") {
            return true;
        }

        example.contains("--select-1") && is_single_item_input(example)
    }

    fn run_or_compile_example(example: &Example<'_>) -> nu_test_support::Result<()> {
        let mut tester = nu_test_support::test();

        if is_headless_example(example.example) {
            let _ = tester.run::<Value>(example.example)?;
            Ok(())
        } else {
            tester.parse_and_compile(example.example).map(|_| ())
        }
    }

    #[test]
    fn test_skim_examples_are_valid() -> nu_test_support::Result<()> {
        for example in SkimCommand.examples() {
            run_or_compile_example(&example)?;
        }

        Ok(())
    }

    #[test]
    fn test_headless_example_detector() {
        assert!(is_headless_example("[one] | skim --select-1"));
        assert!(is_headless_example("[one] | skim --exit-0 'two'"));
        assert!(!is_headless_example("[one two three] | skim --select-1"));
        assert!(!is_headless_example("[Foo Bar] | skim --select-1"));
        assert!(!is_headless_example("[one two] | skim --select-1 --query one"));
    }

    #[test]
    fn test_case_mode_from_flags() {
        assert_eq!(
            case_mode_from_flags(false, false, false, Span::unknown()).unwrap(),
            CaseMatching::Smart
        );
        assert_eq!(
            case_mode_from_flags(true, false, false, Span::unknown()).unwrap(),
            CaseMatching::Respect
        );
        assert_eq!(
            case_mode_from_flags(false, true, false, Span::unknown()).unwrap(),
            CaseMatching::Ignore
        );
        assert_eq!(
            case_mode_from_flags(false, false, true, Span::unknown()).unwrap(),
            CaseMatching::Smart
        );
    }

    #[test]
    fn test_case_mode_from_flags_invalid() {
        assert!(case_mode_from_flags(true, true, false, Span::unknown()).is_err());
        assert!(case_mode_from_flags(true, false, true, Span::unknown()).is_err());
        assert!(case_mode_from_flags(false, true, true, Span::unknown()).is_err());
    }

    #[test]
    fn test_format_skim_item() {
        let config = Config::default();
        let engine_state = EngineState::new();
        let mut stack = Stack::new();
        let comp = StyleComputer::from_config(&engine_state, &mut stack);
        let value = Value::string("apple", Span::unknown());

        let (display, text) = format_skim_item(&value, &config, &comp, false);
        assert_eq!(display, "apple");
        assert_eq!(text, "apple");
    }

    #[test]
    fn test_format_skim_item_ansi() {
        let config = Config::default();
        let engine_state = EngineState::new();
        let mut stack = Stack::new();
        let comp = StyleComputer::from_config(&engine_state, &mut stack);
        let value = Value::string("banana", Span::unknown());

        let (display, text) = format_skim_item(&value, &config, &comp, true);
        assert!(display.contains("banana"));
        assert_eq!(text, "banana");
    }

    #[test]
    fn test_parse_skim_default_options() {
        let options =
            parse_skim_default_options("--prompt 'hello world' --multi --case ignore --query foo")
                .unwrap();
        assert_eq!(options.prompt.as_deref(), Some("hello world"));
        assert_eq!(options.query.as_deref(), Some("foo"));
        assert!(options.multi.unwrap_or(false));
        assert_eq!(options.case.unwrap(), CaseMatching::Ignore);
    }

    #[test]
    fn test_parse_skim_default_options_all_supported_flags() {
        let options = parse_skim_default_options(
            "--bind 'ctrl-j:down' --prompt 'pick' --cmd-prompt 'cmd> ' --multi --tac --no-sort --tiebreak score,length --exact --interactive --query foo --cmd-query bar --regex --color 'fg:blue' --margin '1,2,3,4' --no-height --height 40% --min-height 5 --preview-window right:50% --reverse --tabstop 4 --no-hscroll --no-mouse --inline-info --layout reverse-list --algo clangd --case respect --keep-right --skip-to-pattern ':' --select-1 --exit-0 --sync --no-clear-if-empty --pre-select-n 1 --pre-select-pat 't' --pre-select-items one,two --pre-select-file /tmp/items",
        )
        .unwrap();

        assert_eq!(options.bind, vec!["ctrl-j:down"]);
        assert_eq!(options.prompt.as_deref(), Some("pick"));
        assert_eq!(options.cmd_prompt.as_deref(), Some("cmd> "));
        assert!(options.multi.unwrap_or(false));
        assert!(options.tac.unwrap_or(false));
        assert!(options.no_sort.unwrap_or(false));
        assert_eq!(
            options.tiebreak.unwrap(),
            vec![RankCriteria::Score, RankCriteria::Length]
        );
        assert!(options.exact.unwrap_or(false));
        assert!(options.interactive.unwrap_or(false));
        assert_eq!(options.query.as_deref(), Some("foo"));
        assert_eq!(options.cmd_query.as_deref(), Some("bar"));
        assert!(options.regex.unwrap_or(false));
        assert_eq!(options.color.as_deref(), Some("fg:blue"));
        assert_eq!(options.margin.as_deref(), Some("1,2,3,4"));
        assert!(options.no_height.unwrap_or(false));
        assert_eq!(options.height.as_deref(), Some("40%"));
        assert_eq!(options.min_height.as_deref(), Some("5"));
        assert_eq!(options.preview_window.as_deref(), Some("right:50%"));
        assert!(options.reverse.unwrap_or(false));
        assert_eq!(options.tabstop, Some(4));
        assert!(options.no_hscroll.unwrap_or(false));
        assert!(options.no_mouse.unwrap_or(false));
        assert!(options.inline_info.unwrap_or(false));
        assert_eq!(options.layout.as_deref(), Some("reverse-list"));
        assert_eq!(options.algorithm.unwrap(), FuzzyAlgorithm::Clangd);
        assert_eq!(options.case.unwrap(), CaseMatching::Respect);
        assert!(options.keep_right.unwrap_or(false));
        assert_eq!(options.skip_to_pattern.as_deref(), Some(":"));
        assert!(options.select1.unwrap_or(false));
        assert!(options.exit0.unwrap_or(false));
        assert!(options.sync.unwrap_or(false));
        assert!(options.no_clear_if_empty.unwrap_or(false));
        assert_eq!(options.pre_select_n, Some(1));
        assert_eq!(options.pre_select_pat.as_deref(), Some("t"));
        assert_eq!(
            options.pre_select_items,
            Some(vec!["one".to_string(), "two".to_string()])
        );
        assert_eq!(options.pre_select_file.as_deref(), Some("/tmp/items"));
    }

    fn build_maximal_skim_arguments() -> SkimArguments {
        SkimArguments {
            bind: vec!["ctrl-j:down".to_owned()],
            prompt: Some("pick".to_owned()),
            cmd_prompt: Some("cmd> ".to_owned()),
            multi: true,
            tac: true,
            no_sort: true,
            tiebreak: vec![RankCriteria::Score, RankCriteria::Length],
            exact: true,
            interactive: true,
            query: Some("foo".to_owned()),
            cmd_query: Some("bar".to_owned()),
            regex: true,
            color: Some("fg:blue".to_owned()),
            margin: Some("1,2,3,4".to_owned()),
            no_height: false,
            no_clear: true,
            no_clear_start: true,
            min_height: Some("5".to_owned()),
            height: Some("40%".to_owned()),
            preview_window: Some("right:50%".to_owned()),
            reverse: false,
            ansi: true,
            tabstop: Some(4),
            no_hscroll: true,
            no_mouse: true,
            inline_info: true,
            layout: Some(TuiLayout::ReverseList),
            algorithm: FuzzyAlgorithm::Clangd,
            case: CaseMatching::Respect,
            keep_right: true,
            skip_to_pattern: Some(":".to_owned()),
            select1: true,
            exit0: true,
            sync: true,
            no_clear_if_empty: true,
            pre_select_n: Some(1),
            pre_select_pat: Some("t".to_owned()),
            pre_select_items: vec!["one".to_owned(), "two".to_owned()],
            pre_select_file: Some("items.txt".to_owned()),
            selector: Some(Rc::new(DefaultSkimSelector::default().first_n(1))),
            cmd: None,
            format: None,
            preview: Some(Value::string("preview", Span::unknown())),
        }
    }

    #[test]
    fn test_skim_arguments_to_skim_options_maps_values() {
        let engine_state = EngineState::new();
        let stack = Stack::new();
        let command_context = Arc::new(CommandContext::new(&engine_state, &stack).unwrap());
        let args = build_maximal_skim_arguments();
        let options = args
            .to_skim_options(Span::unknown(), Some(command_context))
            .unwrap();

        assert_eq!(options.bind, vec!["ctrl-j:down"]);
        assert_eq!(options.prompt, "pick");
        assert_eq!(options.cmd_prompt, "cmd> ");
        assert!(options.multi);
        assert!(!options.no_multi);
        assert!(options.tac);
        assert!(options.no_sort);
        assert_eq!(
            options.tiebreak,
            vec![RankCriteria::Score, RankCriteria::Length]
        );
        assert!(options.exact);
        assert!(options.interactive);
        assert_eq!(options.query.as_deref(), Some("foo"));
        assert_eq!(options.cmd_query.as_deref(), Some("bar"));
        assert!(options.regex);
        assert_eq!(options.color.as_deref(), Some("fg:blue"));
        assert_eq!(options.margin, "1,2,3,4");
        assert!(!options.no_height);
        assert_eq!(options.height, "40%");
        assert_eq!(options.min_height, "5");
        assert_eq!(
            format!("{:?}", options.preview_window),
            format!("{:?}", PreviewLayout::from("right:50%"))
        );
        assert!(!options.reverse);
        assert_eq!(options.tabstop, 4);
        assert!(options.no_hscroll);
        assert!(options.no_mouse);
        assert!(options.inline_info);
        assert_eq!(options.layout, TuiLayout::ReverseList);
        assert_eq!(options.algorithm, FuzzyAlgorithm::Clangd);
        assert_eq!(options.case, CaseMatching::Respect);
        assert!(options.keep_right);
        assert_eq!(options.skip_to_pattern.as_deref(), Some(":"));
        assert!(options.select_1);
        assert!(options.exit_0);
        assert!(options.sync);
        assert!(options.no_clear_if_empty);
        assert_eq!(options.pre_select_n, 1);
        assert_eq!(options.pre_select_pat, "t");
        assert_eq!(options.pre_select_items, "one\ntwo");
        assert_eq!(options.pre_select_file.as_deref(), Some("items.txt"));
        assert_eq!(options.preview.as_deref(), Some("preview"));
        assert!(options.selector.is_some());
        assert!(options.cmd.is_none());
    }

    #[test]
    fn test_select_1_auto_accepts_single_match_without_tui()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut options = SkimOptions::default();
        options.query = Some("apple".to_owned());
        options.select_1 = true;
        options.sync = true;
        let options = options.build();

        let output = Skim::run_items(options, ["apple", "banana"])?;
        assert_eq!(output.selected_items.len(), 1);
        assert_eq!(output.selected_items[0].output(), "apple");
        Ok(())
    }

    #[test]
    fn test_exit_0_returns_no_matches_without_tui() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut options = SkimOptions::default();
        options.query = Some("orange".to_owned());
        options.exit_0 = true;
        let options = options.build();

        let output = Skim::run_items(options, ["apple", "banana"])?;
        assert!(output.selected_items.is_empty());
        Ok(())
    }

    #[test]
    fn test_examples_cover_all_named_flags() {
        let signature = SkimCommand.signature();
        let examples = SkimCommand.examples();
        let joined_examples = examples
            .iter()
            .map(|example| example.example.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let missing: Vec<String> = signature
            .named
            .iter()
            .filter_map(|flag| {
                let long = format!("--{}", flag.long);
                let short_present = flag
                    .short
                    .map(|short| joined_examples.contains(&format!("-{}", short)))
                    .unwrap_or(false);
                let long_present = joined_examples.contains(&long);

                if long_present || short_present {
                    None
                } else {
                    Some(flag.long.clone())
                }
            })
            .collect();

        assert!(
            missing.is_empty(),
            "Examples missing named flags: {:?}",
            missing
        );
    }

    #[test]
    fn test_signature_has_no_duplicate_flag_shorts_or_names() {
        let signature = SkimCommand.signature();
        let mut seen_longs = HashSet::new();
        let mut seen_shorts = HashSet::new();

        for flag in signature.named.iter() {
            assert!(
                seen_longs.insert(flag.long.clone()),
                "Duplicate long flag: {}",
                flag.long
            );
            if let Some(short) = flag.short {
                assert!(
                    seen_shorts.insert(short),
                    "Duplicate short flag: -{}",
                    short
                );
            }
        }
    }

    #[test]
    fn test_optional_prompt_is_documented() {
        let signature = SkimCommand.signature();
        assert!(
            signature
                .optional_positional
                .iter()
                .any(|pos| pos.name == "prompt")
        );
        assert!(
            SkimCommand
                .examples()
                .iter()
                .any(|example| example.example.contains("Choose one"))
        );
    }

    #[test]
    fn test_examples() -> nu_test_support::Result {
        nu_test_support::test().examples(SkimCommand)
    }
}
