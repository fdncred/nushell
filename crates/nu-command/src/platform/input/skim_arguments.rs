use nu_engine::command_prelude::*;
use nu_protocol::{Value, engine::Closure};
use regex::Regex;
use skim::binds::KeyMap;
use skim::prelude::{
    CaseMatching, DefaultSkimSelector, FuzzyAlgorithm, RankCriteria, Selector, SkimOptions,
};
use skim::tui::{
    options::{PreviewLayout, TuiLayout},
    statusline::InfoDisplay,
};
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
    pub min_query_length: Option<usize>,
    pub no_sort: Option<bool>,
    pub tiebreak: Option<Vec<RankCriteria>>,
    pub nth: Option<Vec<String>>,
    pub with_nth: Option<Vec<String>>,
    pub delimiter: Option<String>,
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
    pub normalize: Option<bool>,
    pub split_match: Option<char>,
    pub last_match: Option<bool>,
    pub keep_right: Option<bool>,
    pub skip_to_pattern: Option<String>,
    pub selector_icon: Option<String>,
    pub multi_select_icon: Option<String>,
    pub select1: Option<bool>,
    pub exit0: Option<bool>,
    pub sync: Option<bool>,
    pub no_clear_if_empty: Option<bool>,
    pub no_strip_ansi: Option<bool>,
    pub highlight_line: Option<bool>,
    pub show_cmd_error: Option<bool>,
    pub cycle: Option<bool>,
    pub disabled: Option<bool>,
    pub no_info: Option<bool>,
    pub header: Option<String>,
    pub header_lines: Option<usize>,
    pub wrap_items: Option<bool>,
    pub scrollbar: Option<String>,
    pub no_scrollbar: Option<bool>,
    pub history_file: Option<String>,
    pub history_size: Option<usize>,
    pub cmd_history_file: Option<String>,
    pub cmd_history_size: Option<usize>,
    pub read0: Option<bool>,
    pub print0: Option<bool>,
    pub print_query: Option<bool>,
    pub print_cmd: Option<bool>,
    pub print_score: Option<bool>,
    pub print_header: Option<bool>,
    pub print_current: Option<bool>,
    pub output_format: Option<String>,
    pub filter: Option<String>,
    pub popup: Option<String>,
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
    pub min_query_length: Option<usize>,
    pub no_sort: bool,
    pub tiebreak: Vec<RankCriteria>,
    pub nth: Vec<String>,
    pub with_nth: Vec<String>,
    pub delimiter: Option<Regex>,
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
    pub normalize: bool,
    pub split_match: Option<char>,
    pub last_match: bool,
    pub keep_right: bool,
    pub skip_to_pattern: Option<String>,
    pub selector_icon: Option<String>,
    pub multi_select_icon: Option<String>,
    pub select1: bool,
    pub exit0: bool,
    pub sync: bool,
    pub no_clear_if_empty: bool,
    pub no_strip_ansi: bool,
    pub highlight_line: bool,
    pub show_cmd_error: bool,
    pub cycle: bool,
    pub disabled: bool,
    pub no_info: bool,
    pub header: Option<String>,
    pub header_lines: Option<usize>,
    pub wrap_items: bool,
    pub scrollbar: Option<String>,
    pub no_scrollbar: bool,
    pub history_file: Option<String>,
    pub history_size: Option<usize>,
    pub cmd_history_file: Option<String>,
    pub cmd_history_size: Option<usize>,
    pub read0: bool,
    pub print0: bool,
    pub print_query: bool,
    pub print_cmd: bool,
    pub print_score: bool,
    pub print_header: bool,
    pub print_current: bool,
    pub output_format: Option<String>,
    pub filter: Option<String>,
    pub popup: Option<String>,
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
        let min_query_length = call
            .get_flag(engine_state, stack, "min-query-length")?
            .or(defaults.min_query_length);
        let no_sort =
            call.has_flag(engine_state, stack, "no-sort")? || defaults.no_sort.unwrap_or(false);
        let nth = call
            .get_flag::<Vec<String>>(engine_state, stack, "nth")?
            .unwrap_or_else(|| defaults.nth.clone().unwrap_or_default());
        let with_nth = call
            .get_flag::<Vec<String>>(engine_state, stack, "with-nth")?
            .unwrap_or_else(|| defaults.with_nth.clone().unwrap_or_default());
        let delimiter = call
            .get_flag::<Spanned<String>>(engine_state, stack, "delimiter")?
            .map(|value| parse_delimiter(&value))
            .transpose()?
            .or_else(|| {
                defaults
                    .delimiter
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .ok()
                    .flatten()
            });
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
        let no_info =
            call.has_flag(engine_state, stack, "no-info")? || defaults.no_info.unwrap_or(false);
        let normalize =
            call.has_flag(engine_state, stack, "normalize")? || defaults.normalize.unwrap_or(false);
        let split_match = call
            .get_flag::<Spanned<String>>(engine_state, stack, "split-match")?
            .map(|value| parse_single_char_flag("split-match", value))
            .transpose()?
            .or(defaults.split_match);
        let last_match = call.has_flag(engine_state, stack, "last-match")?
            || defaults.last_match.unwrap_or(false);
        let keep_right = call.has_flag(engine_state, stack, "keep-right")?
            || defaults.keep_right.unwrap_or(false);
        let select1 =
            call.has_flag(engine_state, stack, "select-1")? || defaults.select1.unwrap_or(false);
        let exit0 =
            call.has_flag(engine_state, stack, "exit-0")? || defaults.exit0.unwrap_or(false);
        let sync = call.has_flag(engine_state, stack, "sync")? || defaults.sync.unwrap_or(false);
        let no_clear_if_empty = call.has_flag(engine_state, stack, "no-clear-if-empty")?
            || defaults.no_clear_if_empty.unwrap_or(false);
        let no_strip_ansi = call.has_flag(engine_state, stack, "no-strip-ansi")?
            || defaults.no_strip_ansi.unwrap_or(false);
        let highlight_line = call.has_flag(engine_state, stack, "highlight-line")?
            || defaults.highlight_line.unwrap_or(false);
        let show_cmd_error = call.has_flag(engine_state, stack, "show-cmd-error")?
            || defaults.show_cmd_error.unwrap_or(false);
        let cycle = call.has_flag(engine_state, stack, "cycle")? || defaults.cycle.unwrap_or(false);
        let disabled =
            call.has_flag(engine_state, stack, "disabled")? || defaults.disabled.unwrap_or(false);
        let wrap_items =
            call.has_flag(engine_state, stack, "wrap")? || defaults.wrap_items.unwrap_or(false);
        let no_scrollbar = call.has_flag(engine_state, stack, "no-scrollbar")?
            || defaults.no_scrollbar.unwrap_or(false);
        let read0 = call.has_flag(engine_state, stack, "read0")? || defaults.read0.unwrap_or(false);
        let print0 =
            call.has_flag(engine_state, stack, "print0")? || defaults.print0.unwrap_or(false);
        let print_query = call.has_flag(engine_state, stack, "print-query")?
            || defaults.print_query.unwrap_or(false);
        let print_cmd =
            call.has_flag(engine_state, stack, "print-cmd")? || defaults.print_cmd.unwrap_or(false);
        let print_score = call.has_flag(engine_state, stack, "print-score")?
            || defaults.print_score.unwrap_or(false);
        let print_header = call.has_flag(engine_state, stack, "print-header")?
            || defaults.print_header.unwrap_or(false);
        let print_current = call.has_flag(engine_state, stack, "print-current")?
            || defaults.print_current.unwrap_or(false);

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
        let selector_icon: Option<String> = call
            .get_flag(engine_state, stack, "selector")?
            .or_else(|| defaults.selector_icon.clone());
        let multi_select_icon: Option<String> = call
            .get_flag(engine_state, stack, "multi-selector")?
            .or_else(|| defaults.multi_select_icon.clone());
        let header: Option<String> = call
            .get_flag(engine_state, stack, "header")?
            .or_else(|| defaults.header.clone());
        let header_lines: Option<usize> = call
            .get_flag(engine_state, stack, "header-lines")?
            .or(defaults.header_lines);
        let filter: Option<String> = call
            .get_flag(engine_state, stack, "filter")?
            .or_else(|| defaults.filter.clone());
        let scrollbar: Option<String> = call
            .get_flag(engine_state, stack, "scrollbar")?
            .or_else(|| defaults.scrollbar.clone());
        let history_file: Option<String> = call
            .get_flag(engine_state, stack, "history")?
            .or_else(|| defaults.history_file.clone());
        let history_size = call
            .get_flag(engine_state, stack, "history-size")?
            .or(defaults.history_size);
        let cmd_history_file: Option<String> = call
            .get_flag(engine_state, stack, "cmd-history")?
            .or_else(|| defaults.cmd_history_file.clone());
        let cmd_history_size = call
            .get_flag(engine_state, stack, "cmd-history-size")?
            .or(defaults.cmd_history_size);
        let output_format: Option<String> = call
            .get_flag(engine_state, stack, "output-format")?
            .or_else(|| defaults.output_format.clone());
        let popup: Option<String> = call
            .get_flag(engine_state, stack, "popup")?
            .or_else(|| defaults.popup.clone());

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

        let case_sensitive = call.has_flag(engine_state, stack, "case-sensitive")?;
        let ignore_case = call.has_flag(engine_state, stack, "ignore-case")?;
        let smart_case = call.has_flag(engine_state, stack, "smart-case")?;

        let case = if case_sensitive || ignore_case || smart_case {
            case_mode_from_flags(case_sensitive, ignore_case, smart_case, call.head)?
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

        dumb_selector = apply_preselect_n(dumb_selector, defaults.pre_select_n);
        dumb_selector = apply_preselect_pattern(dumb_selector, defaults.pre_select_pat.clone());
        dumb_selector = apply_preselect_items(
            dumb_selector,
            defaults.pre_select_items.clone().unwrap_or_default(),
        );
        if let Some(file_path) = defaults.pre_select_file.clone() {
            let items = read_preselect_file_items(engine_state, stack, &file_path, call.head)?;
            dumb_selector = apply_preselect_items(dumb_selector, items);
        }

        dumb_selector = apply_preselect_n(
            dumb_selector,
            call.get_flag(engine_state, stack, "pre-select-n")?,
        );
        dumb_selector = apply_preselect_pattern(
            dumb_selector,
            call.get_flag::<String>(engine_state, stack, "pre-select-pat")?,
        );
        dumb_selector = apply_preselect_items(
            dumb_selector,
            call.get_flag::<Vec<String>>(engine_state, stack, "pre-select-items")?
                .unwrap_or_default(),
        );
        if let Some(file_path) =
            call.get_flag::<Spanned<String>>(engine_state, stack, "pre-select-file")?
        {
            let items = read_preselect_file_items(engine_state, stack, &file_path.item, call.head)?;
            dumb_selector = apply_preselect_items(dumb_selector, items);
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
            min_query_length,
            no_sort,
            tiebreak,
            nth,
            with_nth,
            delimiter,
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
            normalize,
            split_match,
            last_match,
            ansi,
            keep_right,
            skip_to_pattern,
            selector_icon,
            multi_select_icon,
            select1,
            exit0,
            sync,
            no_clear_if_empty,
            no_strip_ansi,
            highlight_line,
            show_cmd_error,
            cycle,
            disabled,
            no_info,
            header,
            header_lines,
            wrap_items,
            scrollbar,
            no_scrollbar,
            history_file,
            history_size,
            cmd_history_file,
            cmd_history_size,
            read0,
            print0,
            print_query,
            print_cmd,
            print_score,
            print_header,
            print_current,
            output_format,
            filter,
            popup,
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
            .named("min-query-length", SyntaxShape::Number, "Minimum query length required before matches are shown.", None)
            .switch("no-sort", "Do not sort the search result (normally used together with --tac)", None)
            .named("tiebreak", SyntaxShape::List(Box::new(SyntaxShape::String)), "List of sort criteria to apply when the scores are tied.", None)
            .named("nth", SyntaxShape::List(Box::new(SyntaxShape::String)), "Fields to match.", None)
            .named("with-nth", SyntaxShape::List(Box::new(SyntaxShape::String)), "Fields to transform for display.", None)
            .named("delimiter", SyntaxShape::String, "Regex delimiter between fields.", None)
            .switch("exact", "Enable exact-match", Some('e'))
            .switch(
                "interactive",
                "Start skim in interactive(command) mode",
                Some('i'),
            )
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
            .switch("normalize", "Normalize unicode characters before matching.", None)
            .named("split-match", SyntaxShape::String, "Enable split matching with the given separator character.", None)
            .switch("last-match", "Highlight the last match found instead of the first.", None)
            .switch("keep-right", "Keep the right end of the line visible when it's too long", None)
            .named("skip-to-pattern", SyntaxShape::String, "Line will start with the start of the matched pattern", None)
            .named("selector", SyntaxShape::String, "Selected item marker.", None)
            .named("multi-selector", SyntaxShape::String, "Multi-selection marker.", None)
            .switch("select-1", "Automatically select the only match", Some('1'))
            .switch("exit-0", "Exit immediately when there's no match", Some('0'))
            .switch("sync", "Wait for all the options to be available before choosing", None)
            .switch("no-strip-ansi", "Preserve ANSI escape sequences in output when ANSI is enabled.", None)
            .switch("highlight-line", "Highlight the entire current line, not just matched text.", None)
            .switch("show-cmd-error", "Show command errors in interactive command mode.", None)
            .switch("cycle", "Cycle results by wrapping around when scrolling.", None)
            .switch("disabled", "Disable matching entirely.", None)
            .switch("no-info", "Hide the finder info line.", None)
            .named("header", SyntaxShape::String, "Sticky header text.", None)
            .named("header-lines", SyntaxShape::Number, "Treat the first N input lines as sticky header.", None)
            .switch("wrap", "Wrap items in the item list.", None)
            .named("scrollbar", SyntaxShape::String, "Scrollbar thumb indicator.", None)
            .switch("no-scrollbar", "Hide the scrollbar.", None)
            .named("history", SyntaxShape::Filepath, "Search history file.", None)
            .named("history-size", SyntaxShape::Number, "Maximum number of search history entries.", None)
            .named("cmd-history", SyntaxShape::Filepath, "Command history file.", None)
            .named("cmd-history-size", SyntaxShape::Number, "Maximum number of command history entries.", None)
            .switch("read0", "Read NUL-delimited input.", None)
            .switch("print0", "Print NUL-delimited output.", None)
            .switch("print-query", "Print query as first output line.", None)
            .switch("print-cmd", "Print command as first output line (after print-query).", None)
            .switch("print-score", "Print score after each item.", None)
            .switch("print-header", "Print header before items.", None)
            .switch("print-current", "Print the current item before selected results.", None)
            .named("output-format", SyntaxShape::String, "Custom output format string.", None)
            .named("filter", SyntaxShape::String, "Filter-mode query.", None)
            .named("popup", SyntaxShape::String, "Run skim inside a popup layout.", None)
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
        options.min_query_length = self.min_query_length;
        options.no_sort = self.no_sort;
        options.tiebreak = self.tiebreak.clone();
        options.nth = self.nth.clone();
        options.with_nth = self.with_nth.clone();
        options.delimiter = self
            .delimiter
            .clone()
            .unwrap_or_else(|| default_options.delimiter.clone());
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
            self.layout.unwrap_or_default()
        };
        options.algorithm = self.algorithm;
        options.case = self.case;
        options.normalize = self.normalize;
        options.split_match = self.split_match;
        options.last_match = self.last_match;
        options.keep_right = self.keep_right;
        options.skip_to_pattern = self.skip_to_pattern.clone();
        options.selector_icon = self
            .selector_icon
            .clone()
            .unwrap_or_else(|| default_options.selector_icon.clone());
        options.multi_select_icon = self
            .multi_select_icon
            .clone()
            .unwrap_or_else(|| default_options.multi_select_icon.clone());
        options.ansi = self.ansi;
        options.no_strip_ansi = self.no_strip_ansi || self.ansi;
        options.highlight_line = self.highlight_line;
        options.show_cmd_error = self.show_cmd_error;
        options.cycle = self.cycle;
        options.disabled = self.disabled;
        options.no_info = self.no_info;
        options.inline_info = self.inline_info && !self.no_info;
        options.info = if self.no_info {
            InfoDisplay::Hidden
        } else if self.inline_info {
            InfoDisplay::Inline
        } else {
            default_options.info
        };
        options.select_1 = self.select1;
        options.exit_0 = self.exit0;
        // `--sync` can block indefinitely in non-interactive mode; only enable user-requested
        // sync for command mode features, but force it for `--select-1` so skim can
        // deterministically auto-accept a single match without opening the TUI.
        options.sync =
            self.select1 || self.exit0 || (self.sync && (self.interactive || self.cmd.is_some()));
        options.selector = self.selector.clone();
        options.no_clear_if_empty = self.no_clear_if_empty;
        options.header = self.header.clone();
        options.header_lines = self.header_lines.unwrap_or_default();
        options.wrap_items = self.wrap_items;
        options.scrollbar = self
            .scrollbar
            .clone()
            .unwrap_or_else(|| default_options.scrollbar.clone());
        options.no_scrollbar = self.no_scrollbar;
        options.history_file = self.history_file.clone();
        options.history_size = self.history_size.unwrap_or(default_options.history_size);
        options.cmd_history_file = self.cmd_history_file.clone();
        options.cmd_history_size = self
            .cmd_history_size
            .unwrap_or(default_options.cmd_history_size);
        options.read0 = self.read0;
        options.print0 = self.print0;
        options.print_query = self.print_query;
        options.print_cmd = self.print_cmd;
        options.print_score = self.print_score;
        options.print_header = self.print_header;
        options.print_current = self.print_current;
        options.output_format = self.output_format.clone();
        options.filter = self.filter.clone();
        options.popup = self.popup.clone();
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
        options.border = default_options.border;
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
                "min-query-length" => {
                    options.min_query_length = parse_usize_flag(value_opt, &mut tokens);
                }
                "no-sort" => options.no_sort = Some(true),
                "nth" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.nth = Some(split_csv_like(&value));
                    }
                }
                "with-nth" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.with_nth = Some(split_csv_like(&value));
                    }
                }
                "delimiter" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.delimiter = Some(value);
                    }
                }
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
                "no-info" => options.no_info = Some(true),
                "keep-right" => options.keep_right = Some(true),
                "normalize" => options.normalize = Some(true),
                "last-match" => options.last_match = Some(true),
                "select-1" => options.select1 = Some(true),
                "exit-0" => options.exit0 = Some(true),
                "sync" => options.sync = Some(true),
                "no-clear-if-empty" => options.no_clear_if_empty = Some(true),
                "no-strip-ansi" => options.no_strip_ansi = Some(true),
                "ansi" => options.ansi = Some(true),
                "highlight-line" => options.highlight_line = Some(true),
                "show-cmd-error" => options.show_cmd_error = Some(true),
                "cycle" => options.cycle = Some(true),
                "disabled" => options.disabled = Some(true),
                "wrap" => options.wrap_items = Some(true),
                "no-scrollbar" => options.no_scrollbar = Some(true),
                "read0" => options.read0 = Some(true),
                "print0" => options.print0 = Some(true),
                "print-query" => options.print_query = Some(true),
                "print-cmd" => options.print_cmd = Some(true),
                "print-score" => options.print_score = Some(true),
                "print-header" => options.print_header = Some(true),
                "print-current" => options.print_current = Some(true),
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
                "selector" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.selector_icon = Some(value);
                    }
                }
                "multi-selector" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.multi_select_icon = Some(value);
                    }
                }
                "header" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.header = Some(value);
                    }
                }
                "header-lines" => {
                    options.header_lines = parse_usize_flag(value_opt, &mut tokens);
                }
                "filter" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.filter = Some(value);
                    }
                }
                "scrollbar" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.scrollbar = Some(value);
                    }
                }
                "history" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.history_file = Some(value);
                    }
                }
                "history-size" => {
                    options.history_size = parse_usize_flag(value_opt, &mut tokens);
                }
                "cmd-history" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.cmd_history_file = Some(value);
                    }
                }
                "cmd-history-size" => {
                    options.cmd_history_size = parse_usize_flag(value_opt, &mut tokens);
                }
                "output-format" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.output_format = Some(value);
                    }
                }
                "popup" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.popup = Some(value);
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
                "split-match" => {
                    if let Some(value) = take_opt_value(value_opt, &mut tokens) {
                        options.split_match = value.chars().next();
                    }
                }
                "tabstop" => {
                    options.tabstop = parse_usize_flag(value_opt, &mut tokens);
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
                    options.pre_select_n = parse_usize_flag(value_opt, &mut tokens);
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

        if let Some(stripped) = token.strip_prefix('-') {
            let mut chars = stripped.chars().peekable();
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

fn parse_delimiter(value: &Spanned<String>) -> Result<Regex, ShellError> {
    Regex::new(&value.item).map_err(|_| ShellError::InvalidValue {
        actual: value.item.clone(),
        valid: "a valid regex delimiter".to_owned(),
        span: value.span,
    })
}

fn parse_single_char_flag(flag_name: &str, value: Spanned<String>) -> Result<char, ShellError> {
    let mut chars = value.item.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => Ok(ch),
        _ => Err(ShellError::InvalidValue {
            actual: value.item,
            valid: format!("a single character for --{flag_name}"),
            span: value.span,
        }),
    }
}

fn parse_usize_flag<I>(
    value_opt: Option<String>,
    tokens: &mut std::iter::Peekable<I>,
) -> Option<usize>
where
    I: Iterator<Item = String>,
{
    take_opt_value(value_opt, tokens).and_then(|value| value.parse::<usize>().ok())
}

fn apply_preselect_n(
    selector: Option<DefaultSkimSelector>,
    count: Option<usize>,
) -> Option<DefaultSkimSelector> {
    match count {
        Some(count) => Some(selector.unwrap_or_default().first_n(count)),
        None => selector,
    }
}

fn apply_preselect_pattern(
    selector: Option<DefaultSkimSelector>,
    pattern: Option<String>,
) -> Option<DefaultSkimSelector> {
    match pattern {
        Some(pattern) => Some(selector.unwrap_or_default().regex(&pattern)),
        None => selector,
    }
}

fn apply_preselect_items(
    selector: Option<DefaultSkimSelector>,
    items: Vec<String>,
) -> Option<DefaultSkimSelector> {
    if items.is_empty() {
        selector
    } else {
        Some(selector.unwrap_or_default().preset(items))
    }
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
