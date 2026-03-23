use nu_engine::command_prelude::*;
use nu_protocol::OutDest;
use std::io::Write;

#[derive(Clone)]
pub struct Echo;

impl Command for Echo {
    fn name(&self) -> &str {
        "echo"
    }

    fn description(&self) -> &str {
        "Prints its arguments like `print`, while still supporting pipes and redirection."
    }

    fn signature(&self) -> Signature {
        Signature::build("echo")
            .input_output_types(vec![(Type::Nothing, Type::Any)])
            .rest("rest", SyntaxShape::Any, "The values to echo.")
            .category(Category::Core)
    }

    fn extra_description(&self) -> &str {
        "At runtime, `echo` drains output according to Nushell's redirection mode.
This means it prints immediately in normal command position (like `print`),
but still feeds values into a pipe (`|`) or file redirection (`o>`, `o+e>`, etc.).

When evaluated in a value-collection context (such as const evaluation),
it keeps value semantics: no args produce an empty string, one arg returns
that value, and multiple args return a list."
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let args = call.rest(engine_state, stack, 0)?;
        if matches!(
            stack.pipe_stdout(),
            Some(OutDest::Pipe | OutDest::PipeSeparate | OutDest::Value)
        ) {
            return echo_impl(args, call.head);
        }
        if matches!(
            stack.removed_pipe_stdout(),
            Some(OutDest::Pipe | OutDest::PipeSeparate | OutDest::Value)
        ) {
            let value = echo_impl(args, call.head)?.into_value(call.head)?;
            stack.push_semicolon_drained_value(value);
            return Ok(PipelineData::empty());
        }

        echo_print_like(args, call.head, engine_state, stack)?;
        Ok(PipelineData::empty())
    }

    fn run_const(
        &self,
        working_set: &StateWorkingSet,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let args = call.rest_const(working_set, 0)?;
        echo_impl(args, call.head)
    }

    fn is_const(&self) -> bool {
        true
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Put a list of numbers in the pipeline. This is the same as [1 2 3].",
                example: "echo 1 2 3",
                result: Some(Value::list(
                    vec![Value::test_int(1), Value::test_int(2), Value::test_int(3)],
                    Span::test_data(),
                )),
            },
            Example {
                description: "Returns the piped-in value, by using the special $in variable to obtain it.",
                example: "echo $in",
                result: None,
            },
        ]
    }
}

fn echo_impl(mut args: Vec<Value>, head: Span) -> Result<PipelineData, ShellError> {
    let value = match args.len() {
        0 => Value::string("", head),
        1 => args.pop().expect("one element"),
        _ => Value::list(args, head),
    };
    Ok(value.into_pipeline_data())
}

fn echo_print_like(
    args: Vec<Value>,
    head: Span,
    engine_state: &EngineState,
    stack: &mut Stack,
) -> Result<(), ShellError> {
    let values = if args.is_empty() {
        vec![Value::string("", head)]
    } else {
        args
    };

    match stack.stdout() {
        OutDest::Pipe | OutDest::PipeSeparate | OutDest::Value => Ok(()),
        OutDest::Print | OutDest::Inherit => {
            for value in values {
                value
                    .into_pipeline_data()
                    .print_table(engine_state, stack, false, false)?;
            }
            Ok(())
        }
        OutDest::File(file) => {
            let config = engine_state.get_config();
            let mut writer = file.as_ref();
            for value in values {
                if let Value::Error { error, .. } = value {
                    return Err(*error);
                }

                let mut out = value.to_expanded_string("\n", config);
                out.push('\n');
                writer
                    .write_all(out.as_bytes())
                    .map_err(|err| ShellError::Io(IoError::new_internal(err, "write failed")))?;
            }
            writer
                .flush()
                .map_err(|err| ShellError::Io(IoError::new_internal(err, "flush failed")))?;
            Ok(())
        }
        OutDest::Null => {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_examples() -> nu_test_support::Result {
        use super::Echo;
        nu_test_support::test().examples(Echo)
    }
}
