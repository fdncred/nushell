use nu_color_config::StyleComputer;
use nu_engine::{ClosureEval, command_prelude::*};
use nu_protocol::{Example, Value};
use skim::prelude::Skim;
use std::sync::Arc;
use crate::platform::input::skim_arguments::SkimArguments;
use crate::platform::input::skim_context::{CommandContext, MapperFlag, NuItem};
use crate::platform::input::skim_format::{
    SkimValueItem, format_skim_item_with_closure, preview_skim_item_with_closure,
};

#[derive(Clone)]
pub struct SkimCommand;

impl Command for SkimCommand {
    fn name(&self) -> &str {
        "input skim"
    }

    fn signature(&self) -> Signature {
        SkimArguments::add_to_signature(Signature::build("input skim"))
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
            PipelineData::ListStream(..) if (skim_args.interactive || skim_args.cmd.is_some()) && !index_flag => {
                // In interactive/cmd mode, stream ListStream items directly to skim so the
                // UI can start immediately while upstream input is still being produced.
                let (tx, rx) = skim::prelude::unbounded();
                let context = command_context.clone();

                std::thread::spawn(move || {
                    for value in input {
                        let item = Arc::new(NuItem::new(context.clone(), value))
                            as Arc<dyn skim::prelude::SkimItem>;
                        if tx.send(vec![item]).is_err() {
                            break;
                        }
                    }
                });

                let skim_output = Skim::run_with(options, Some(rx)).map_err(|err| {
                    ShellError::ExternalCommand {
                        label: "Failed to run skim".into(),
                        help: err.to_string(),
                        span: head,
                    }
                })?;

                let values = skim_output
                    .selected_items
                    .iter()
                    .filter_map(|item| {
                        item.as_any()
                            .downcast_ref::<NuItem>()
                            .map(|item| item.value.clone())
                    })
                    .collect::<Vec<_>>();

                if skim_output.is_abort {
                    return Ok(Value::nothing(head).into_pipeline_data());
                }

                let result = if multi {
                    Value::list(values, head)
                } else {
                    values.into_iter().next().unwrap_or_else(|| Value::nothing(head))
                };

                return Ok(result.into_pipeline_data());
            }
            PipelineData::ListStream(..) => {
                let (tx, rx) = skim::prelude::unbounded();
                let mut values = Vec::new();
                let mut batch: Vec<Arc<dyn skim::prelude::SkimItem>> = Vec::with_capacity(1024);

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
                        value: value.clone(),
                        display,
                        text,
                        preview,
                        index: idx,
                        ansi: skim_args.ansi,
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
            PipelineData::ByteStream(stream, ..) => {
                let span = stream.span();
                let text = stream.into_string()?;
                let values = if text.is_empty() {
                    Vec::new()
                } else {
                    text.lines()
                        .map(|line| Value::string(line.to_owned(), span))
                        .collect()
                };

                if values.is_empty() {
                    return Err(ShellError::TypeMismatch {
                        err_message:
                            "expected a list, range, or byte stream with at least one item"
                                .to_string(),
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
                            value: value.clone(),
                            display,
                            text,
                            preview,
                            index: idx,
                            ansi: skim_args.ansi,
                        })
                    })
                    .collect::<Result<Vec<_>, ShellError>>()?;

                let (tx, rx) = skim::prelude::unbounded();
                for chunk in items.chunks(1024) {
                    let _ = tx.send(
                        chunk
                            .iter()
                            .map(|i| Arc::new(i.clone()) as Arc<dyn skim::prelude::SkimItem>)
                            .collect::<Vec<_>>(),
                    );
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
                            value: value.clone(),
                            display,
                            text,
                            preview,
                            index: idx,
                            ansi: skim_args.ansi,
                        })
                    })
                    .collect::<Result<Vec<_>, ShellError>>()?;

                let (tx, rx) = skim::prelude::unbounded();
                for chunk in items.chunks(1024) {
                    let _ = tx.send(
                        chunk
                            .iter()
                            .map(|i| Arc::new(i.clone()) as Arc<dyn skim::prelude::SkimItem>)
                            .collect::<Vec<_>>(),
                    );
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
            PipelineData::Value(
                Value::String {
                    val, internal_span, ..
                },
                ..,
            ) => {
                let values: Vec<Value> = if val.is_empty() {
                    Vec::new()
                } else {
                    val.lines()
                        .map(|line| Value::string(line.to_owned(), internal_span))
                        .collect()
                };

                if values.is_empty() {
                    return Err(ShellError::TypeMismatch {
                        err_message: "expected a non-empty string, list, range, or byte stream"
                            .to_string(),
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
                            value: value.clone(),
                            display,
                            text,
                            preview,
                            index: idx,
                            ansi: skim_args.ansi,
                        })
                    })
                    .collect::<Result<Vec<_>, ShellError>>()?;

                let (tx, rx) = skim::prelude::unbounded();
                for chunk in items.chunks(1024) {
                    let _ = tx.send(
                        chunk
                            .iter()
                            .map(|i| Arc::new(i.clone()) as Arc<dyn skim::prelude::SkimItem>)
                            .collect::<Vec<_>>(),
                    );
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
            _ => {
                return Err(ShellError::TypeMismatch {
                    err_message: "expected a list, range, byte stream, or string".to_string(),
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
            Example {
                // working
                description: "Show a custom prompt before the search box.",
                example: "[1 2 3 4 5] | input skim 'Choose one'",
                result: None,
            },
            Example {
                // working
                description: "Show a custom prompt using the named prompt flag.",
                example: "[one two three] | input skim --prompt 'Pick one'",
                result: None,
            },
            Example {
                // working
                description: "Use a custom key binding.",
                example: "[Foo Bar] | input skim --bind {'ctrl-j':'down'} 'Select item'",
                result: None,
            },
            Example {
                // working
                description: "Allow selecting multiple items and preserve order.",
                example: "[Banana Kiwi Pear] | input skim --multi --tac --no-sort 'Select fruit'",
                result: None,
            },
            Example {
                // working
                description: "Enable ANSI color support for displayed items.",
                example: "[\"\u{1b}[31mapple\u{1b}[0m\" \"banana\"] | input skim --ansi --query apple",
                result: None,
            },
            Example {
                // working
                description: "Search with regular expressions.",
                example: "[foo bar baz] | input skim --regex 'regex> '",
                result: None,
            },
            Example { // working
                description: "Use sort tiebreak criteria with byte stream input.",
                example: "open Cargo.toml --raw | input skim --tiebreak [score length]",
                result: None,
            },
            Example { // NOT-working. If this is supposed to color the items in the list, it's not doing that. It's not clear what
                      // color configuration means in this context.
                description: "Set a color theme and window margin.",
                example: "[one two] | input skim --color 'fg:blue,fg+:black,bg+:yellow' --margin '1,2,1,2' 'Choose'",
                result: None,
            },
            Example {
                // working
                description: "Disable and configure window height.",
                example: "[one two three] | input skim --no-height --height 30% --min-height 10 'Small> '",
                result: None,
            },
            Example {
                // working
                description: "Disable screen clearing on start and exit.",
                example: "[one two] | input skim --no-clear-start --no-clear --no-clear-if-empty 'Keep visible'",
                result: None,
            },
            Example {
                // working
                description: "Use reverse layout and keep the right side visible.",
                example: "[long-line another] | input skim --reverse --layout reverse --keep-right 'Navigate'",
                result: None,
            },
            Example {
                // working
                description: "Control tab width and input behavior.",
                example: "[\"one\ttwo\"] | input skim --tabstop 4 --no-hscroll --no-mouse --inline-info 'Show'",
                result: None,
            },
            Example {
                // working
                description: "Use a different fuzzy matching algorithm and case mode.",
                example: "[foo bar] | input skim --algo clangd --case ignore 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Enable exact matching instead of fuzzy match.",
                example: "[foo bar] | input skim --exact 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Match case sensitively.",
                example: "[Foo foo] | input skim --case-sensitive 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Match case insensitively.",
                example: "[Foo foo] | input skim --ignore-case 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Use smart case matching.",
                example: "[Foo foo] | input skim --smart-case 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Use a preview window layout.",
                example: "[one two] | input skim --preview-window right:50% --preview {||} 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Pre-select items read from a file.",
                example: "let preselect = ($nu.temp-path | path join 'skim-preselect.txt'); ['two'] | str join (char nl) | save --force $preselect; [one two three] | input skim --pre-select-file $preselect",
                result: None,
            },
            Example {
                // working
                description: "Skip to the matched pattern in each line.",
                example: "[a:1 b:2] | input skim --skip-to-pattern ':' 'prompt> '",
                result: None,
            },
            Example {
                // working
                description: "Select only one match without opening skim.",
                example: "[one] | input skim --select-1 --query one",
                result: None,
            },
            Example {
                // working
                description: "Exit with code 0 if there is no match.",
                example: "[one] | input skim --exit-0 --query missing",
                result: None,
            },
            Example {
                // working
                description: "Wait for input to finish before showing results.",
                example: "[one two three] | input skim --sync --query one --select-1 'Sync search'",
                result: None,
            },
            Example {
                // working
                description: "Use a predicate to pre-select matching items.",
                example: "[one two three] | input skim --pre-select {|| $in | str starts-with 't'}",
                result: None,
            },
            Example {
                // working
                description: "Format and preview values while selecting.",
                example: "ps | input skim --format {get name} --preview {||}",
                result: None,
            },
            Example { // working
                description: "Use interactive mode with command mode prompt and query.",
                example: "glob **/*.rs | input skim --interactive --cmd-query test --cmd-prompt 'cmd> ' --cmd {|q| $q}",
                result: None,
            },
            Example {
                // working
                description: "Return the selected item index instead of the value.",
                example: "[Banana Kiwi Pear] | input skim --index",
                result: None,
            },
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::platform::input::skim_format::{SkimValueItem, format_skim_item};
    use nu_protocol::{Config, Example, Span, Value};
    use std::collections::HashSet;

    fn is_single_item_input(example: &str) -> bool {
        let example = example.trim();
        if let Some(pipe_pos) = example.find("| input skim") {
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
        assert!(is_headless_example("[one] | input skim --select-1"));
        assert!(is_headless_example("[one] | input skim --exit-0 'two'"));
        assert!(!is_headless_example(
            "[one two three] | input skim --select-1"
        ));
        assert!(!is_headless_example("[Foo Bar] | input skim --select-1"));
        assert!(!is_headless_example(
            "[one two] | input skim --select-1 --query one"
        ));
    }

    #[test]
    fn test_case_mode_from_flags() {
        assert_eq!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                false,
                false,
                false,
                Span::unknown()
            )
            .unwrap(),
            skim::prelude::CaseMatching::Smart
        );
        assert_eq!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                true,
                false,
                false,
                Span::unknown()
            )
            .unwrap(),
            skim::prelude::CaseMatching::Respect
        );
        assert_eq!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                false,
                true,
                false,
                Span::unknown()
            )
            .unwrap(),
            skim::prelude::CaseMatching::Ignore
        );
        assert_eq!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                false,
                false,
                true,
                Span::unknown()
            )
            .unwrap(),
            skim::prelude::CaseMatching::Smart
        );
    }

    #[test]
    fn test_case_mode_from_flags_invalid() {
        assert!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                true,
                true,
                false,
                Span::unknown()
            )
            .is_err()
        );
        assert!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                true,
                false,
                true,
                Span::unknown()
            )
            .is_err()
        );
        assert!(
            crate::platform::input::skim_arguments::case_mode_from_flags(
                false,
                true,
                true,
                Span::unknown()
            )
            .is_err()
        );
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
        let options = crate::platform::input::skim_arguments::parse_skim_default_options(
            "--prompt 'hello world' --multi --case ignore --query foo",
        )
        .unwrap();
        assert_eq!(options.prompt.as_deref(), Some("hello world"));
        assert_eq!(options.query.as_deref(), Some("foo"));
        assert!(options.multi.unwrap_or(false));
        assert_eq!(options.case.unwrap(), skim::prelude::CaseMatching::Ignore);
    }

    #[test]
    fn test_parse_skim_default_options_all_supported_flags() {
        let options = crate::platform::input::skim_arguments::parse_skim_default_options(
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
            vec![
                skim::prelude::RankCriteria::Score,
                skim::prelude::RankCriteria::Length
            ]
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
        assert_eq!(
            options.algorithm.unwrap(),
            skim::prelude::FuzzyAlgorithm::Clangd
        );
        assert_eq!(options.case.unwrap(), skim::prelude::CaseMatching::Respect);
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

    fn build_maximal_skim_arguments() -> crate::platform::input::skim_arguments::SkimArguments {
        crate::platform::input::skim_arguments::SkimArguments {
            bind: vec!["ctrl-j:down".to_owned()],
            prompt: Some("pick".to_owned()),
            cmd_prompt: Some("cmd> ".to_owned()),
            multi: true,
            tac: true,
            no_sort: true,
            tiebreak: vec![
                skim::prelude::RankCriteria::Score,
                skim::prelude::RankCriteria::Length,
            ],
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
            layout: Some(skim::tui::options::TuiLayout::ReverseList),
            algorithm: skim::prelude::FuzzyAlgorithm::Clangd,
            case: skim::prelude::CaseMatching::Respect,
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
            selector: Some(std::rc::Rc::new(
                skim::prelude::DefaultSkimSelector::default().first_n(1),
            )),
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
            vec![
                skim::prelude::RankCriteria::Score,
                skim::prelude::RankCriteria::Length
            ]
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
            format!("{:?}", skim::tui::options::PreviewLayout::from("right:50%"))
        );
        assert!(!options.reverse);
        assert_eq!(options.tabstop, 4);
        assert!(options.no_hscroll);
        assert!(options.no_mouse);
        assert!(options.inline_info);
        assert_eq!(options.layout, skim::tui::options::TuiLayout::ReverseList);
        assert_eq!(options.algorithm, skim::prelude::FuzzyAlgorithm::Clangd);
        assert_eq!(options.case, skim::prelude::CaseMatching::Respect);
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
    fn test_skim_options_preserves_ansi_sequences() {
        let engine_state = EngineState::new();
        let stack = Stack::new();
        let command_context = Arc::new(CommandContext::new(&engine_state, &stack).unwrap());
        let mut args = build_maximal_skim_arguments();
        args.ansi = true;

        let options = args
            .to_skim_options(Span::unknown(), Some(command_context))
            .unwrap();

        assert!(options.ansi);
        assert!(options.no_strip_ansi);
    }

    #[test]
    fn test_select_1_enables_sync() {
        let engine_state = EngineState::new();
        let stack = Stack::new();
        let command_context = Arc::new(CommandContext::new(&engine_state, &stack).unwrap());
        let mut args = build_maximal_skim_arguments();
        args.select1 = true;
        args.sync = false;

        let options = args
            .to_skim_options(Span::unknown(), Some(command_context))
            .unwrap();

        assert!(options.select_1);
        assert!(options.sync);
    }

    #[test]
    fn test_skim_value_item_stores_original_value() {
        let value = Value::string("apple", Span::unknown());
        let item = SkimValueItem {
            value: value.clone(),
            display: "apple".to_owned(),
            text: "apple".to_owned(),
            preview: None,
            index: 0,
            ansi: false,
        };

        assert_eq!(item.value, value);
    }

    #[test]
    fn test_select_1_auto_accepts_single_match_without_tui()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut options = skim::prelude::SkimOptions::default();
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
    fn test_exit_0_returns_no_matches_without_tui()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut options = skim::prelude::SkimOptions::default();
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
