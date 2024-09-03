use nu_engine::command_prelude::*;
use nu_protocol::engine::CommandType;

#[derive(Clone)]
pub struct Return;

impl Command for Return {
    fn name(&self) -> &str {
        "return"
    }

    fn description(&self) -> &str {
        "Return early from a function."
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build("return")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .optional(
                "return_value",
                SyntaxShape::Any,
                "Optional value to return.",
            )
            .category(Category::Core)
    }

    fn extra_description(&self) -> &str {
        r#"This command is a parser keyword. For details, check:
  https://www.nushell.sh/book/thinking_in_nu.html"#
    }

    fn command_type(&self) -> CommandType {
        CommandType::Keyword
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let return_value: Option<Value> = call.opt(engine_state, stack, 0)?;
        let value = return_value.clone().unwrap_or(Value::nothing(call.head));
        match (input.is_nothing(), &return_value.is_none()) {
            // If both input and return_value are nothing, return value (as before this change)
            (true, true) => Err(ShellError::Return {
                span: call.head,
                value: Box::new(value),
            }),
            // If input is nothing and return_value is not, return return_value
            (true, false) => Err(ShellError::Return {
                span: call.head,
                value: Box::new(value),
            }),
            // If input is not nothing, return input
            (false, true) => Err(ShellError::Return {
                span: call.head,
                value: Box::new(input.into_value(call.head)?),
            }),
            // If both input and return_value are something, maybe return -1? since we don't know which to return
            (false, false) => Err(ShellError::Return {
                span: call.head,
                value: Box::new(Value::test_int(-1)),
            }),
        }
    }

    fn examples(&self) -> Vec<Example> {
        vec![
            Example {
                description: "Return early",
                example: r#"def foo [] { return }"#,
                result: None,
            },
            Example {
                description: "Return with a value",
                example: r#"def foo [x: int] { return $x }"#,
                result: None,
            },
            Example {
                description: "Return with a value piped into return",
                example: r#"def foo [x: int] { $x | return }"#,
                result: None,
            },
        ]
    }
}
