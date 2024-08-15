use nu_engine::command_prelude::*;

#[derive(Clone)]
pub struct SubCommand;

impl Command for SubCommand {
    fn name(&self) -> &str {
        "commandline edit"
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .optional_named_flag(
                "append",
                "appends the string to the end of the buffer",
                Some('a'),
            )
            .optional_named_flag(
                "insert",
                "inserts the string into the buffer at the cursor position",
                Some('i'),
            )
            .optional_named_flag(
                "replace",
                "replaces the current contents of the buffer (default)",
                Some('r'),
            )
            .required_positional_arg(
                "str",
                SyntaxShape::String,
                "the string to perform the operation with",
            )
            .category(Category::Core)
    }

    fn usage(&self) -> &str {
        "Modify the current command line input buffer."
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["repl", "interactive"]
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let str: String = call.req(engine_state, stack, 0)?;
        let mut repl = engine_state.repl_state.lock().expect("repl state mutex");
        if call.has_flag(engine_state, stack, "append")? {
            repl.buffer.push_str(&str);
        } else if call.has_flag(engine_state, stack, "insert")? {
            let cursor_pos = repl.cursor_pos;
            repl.buffer.insert_str(cursor_pos, &str);
            repl.cursor_pos += str.len();
        } else {
            repl.buffer = str;
            repl.cursor_pos = repl.buffer.len();
        }
        Ok(Value::nothing(call.head).into_pipeline_data())
    }
}
