use nu_engine::{ClosureEval, ClosureEvalOnce, command_prelude::*};
use nu_protocol::ast::PathMember;

#[derive(Clone)]
pub struct Update;

impl Command for Update {
    fn name(&self) -> &str {
        "update"
    }

    fn signature(&self) -> Signature {
        Signature::build("update")
            .input_output_types(vec![
                (Type::record(), Type::record()),
                (Type::table(), Type::table()),
                (
                    Type::List(Box::new(Type::Any)),
                    Type::List(Box::new(Type::Any)),
                ),
            ])
            .required(
                "field",
                SyntaxShape::CellPath,
                "The name of the column to update.",
            )
            .required(
                "replacement value",
                SyntaxShape::Any,
                "The new value to give the cell(s), or a closure to create the value.",
            )
            .allow_variants_without_examples(true)
            .category(Category::Filters)
    }

    fn description(&self) -> &str {
        "Update an existing column to have a new value."
    }

    fn extra_description(&self) -> &str {
        "When updating a column, the closure will be run for each row, and the current row will be passed as the first argument. \
Referencing `$in` inside the closure will provide the value at the column for the current row.

When updating a specific index, the closure will instead be run once. The first argument to the closure and the `$in` value will both be the current value at the index."
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        update(engine_state, stack, call, input)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Update a column value.",
                example: "{'name': 'nu', 'stars': 5} | update name 'Nushell'",
                result: Some(Value::test_record(record! {
                    "name" =>  Value::test_string("Nushell"),
                    "stars" => Value::test_int(5),
                })),
            },
            Example {
                description: "Use a closure to alter each value in the 'authors' column to a single string.",
                example: "[[project, authors]; ['nu', ['Andrés', 'JT', 'Yehuda']]] | update authors {|row| $row.authors | str join ',' }",
                result: Some(Value::test_list(vec![Value::test_record(record! {
                    "project" => Value::test_string("nu"),
                    "authors" => Value::test_string("Andrés,JT,Yehuda"),
                })])),
            },
            Example {
                description: "Implicitly use the `$in` value in a closure to update 'authors'.",
                example: "[[project, authors]; ['nu', ['Andrés', 'JT', 'Yehuda']]] | update authors { str join ',' }",
                result: Some(Value::test_list(vec![Value::test_record(record! {
                    "project" => Value::test_string("nu"),
                    "authors" => Value::test_string("Andrés,JT,Yehuda"),
                })])),
            },
            Example {
                description: "Update a value at an index in a list.",
                example: "[1 2 3] | update 1 4",
                result: Some(Value::test_list(vec![
                    Value::test_int(1),
                    Value::test_int(4),
                    Value::test_int(3),
                ])),
            },
            Example {
                description: "Use a closure to compute a new value at an index.",
                example: "[1 2 3] | update 1 {|i| $i + 2 }",
                result: Some(Value::test_list(vec![
                    Value::test_int(1),
                    Value::test_int(4),
                    Value::test_int(3),
                ])),
            },
        ]
    }
}

fn update(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
    input: PipelineData,
) -> Result<PipelineData, ShellError> {
    let head = call.head;
    let cell_path: CellPath = call.req(engine_state, stack, 0)?;
    let replacement: Value = call.req(engine_state, stack, 1)?;
    let metadata = input.metadata().clone();

    // clones used when we need to evaluate closures inside a streaming map.
    // capturing the originals would tie the closure's lifetime to the
    // enclosing function, which isn't `'static` and leads to borrow errors.
    let engine_clone = engine_state.clone();
    let stack_clone = stack.clone();

    // we often need a owned copy of the cell path members when moving into
    // closures; keep a separate variable to avoid borrowing `cell_path`.
    let members = cell_path.members.clone();

    // If reordering is enabled and the cell path contains an integer anywhere,
    // collapse the incoming pipeline into a single value.  The default
    // evaluation for `update` pulls list elements out of the pipe one at a
    // time which prevents the writer from knowing its index; reordering
    // semantics need to target a specific row, so executing against the whole
    // list is necessary.
    let reorder_needed = nu_experimental::REORDER_CELL_PATHS.get()
        && members.iter().any(|m| matches!(m, PathMember::Int { .. }));

    if reorder_needed {
        // collect the entire incoming pipeline into a list to give the writer
        // context about the index when the cell-path is reordered.  Using
        // `into_value` would collapse a single-element stream into the value
        // itself, losing the fact that it belonged to a list.
        let collected: Vec<Value> = input.into_iter().collect();
        let mut value = Value::list(collected, head);

        if let Value::Closure { val, .. } = replacement {
            match (members.first(), &mut value) {
                (Some(PathMember::String { .. }), Value::List { vals, .. }) => {
                    let mut closure = ClosureEval::new(engine_state, stack, *val);
                    for val in vals {
                        update_value_by_closure(val, &mut closure, head, &members, false)?;
                    }
                }
                (first, _) => {
                    update_single_value_by_closure(
                        &mut value,
                        ClosureEvalOnce::new(engine_state, stack, *val),
                        head,
                        &members,
                        matches!(first, Some(PathMember::Int { .. })),
                    )?;
                }
            }
        } else {
            value.update_data_at_cell_path(&members, replacement)?;
        }

        return Ok(value.into_pipeline_data_with_metadata(metadata));
    }

    let input = match input.try_into_stream(engine_state) {
        Ok(input) | Err(input) => input,
    };

    match input {
        PipelineData::Value(mut value, metadata) => {
            if let Value::Closure { val, .. } = replacement {
                match (members.first(), &mut value) {
                    (Some(PathMember::String { .. }), Value::List { vals, .. }) => {
                        let mut closure = ClosureEval::new(engine_state, stack, *val);
                        for val in vals {
                            update_value_by_closure(
                                val,
                                &mut closure,
                                head,
                                &cell_path.members,
                                false,
                            )?;
                        }
                    }
                    (first, _) => {
                        update_single_value_by_closure(
                            &mut value,
                            ClosureEvalOnce::new(engine_state, stack, *val),
                            head,
                            &cell_path.members,
                            matches!(first, Some(PathMember::Int { .. })),
                        )?;
                    }
                }
            } else {
                value.update_data_at_cell_path(&members, replacement)?;
            }
            Ok(value.into_pipeline_data_with_metadata(metadata))
        }
        PipelineData::ListStream(stream, metadata) => {
            // If the user has enabled path reordering and the cell path
            // contains an integer *after* an initial string segment, we need
            // to treat the list as a whole rather than updating every element
            // individually.  The experimental option rewrites a path like
            // `foo.0.bar` to `0.foo.bar`; we mimic that by pulling the first
            // integer member out of the path, walking the stream to that index,
            // and applying the remainder of the path to the selected element.
            if nu_experimental::REORDER_CELL_PATHS.get()
                && let Some((
                    int_pos,
                    PathMember::Int {
                        val,
                        span: path_span,
                        optional,
                    },
                )) = members
                    .iter()
                    .enumerate()
                    .find(|(_, m)| matches!(m, PathMember::Int { .. }))
                && int_pos > 0 {
                    // build a new member list with the integer removed
                    let mut new_members: Vec<PathMember> = members.clone();
                    // safe to remove because int_pos < len
                    new_members.remove(int_pos);

                    let mut stream = stream.into_iter();
                    let mut pre_elems = vec![];

                    // val, path_span, optional are references, so deref for use
                    let target_idx = *val;
                    let path_span = *path_span;
                    let optional = *optional;

                    for idx in 0..=target_idx {
                        if let Some(v) = stream.next() {
                            pre_elems.push(v);
                        } else if optional {
                            return Ok(pre_elems
                                .into_iter()
                                .chain(stream)
                                .into_pipeline_data_with_metadata(
                                    head,
                                    engine_state.signals().clone(),
                                    metadata,
                                ));
                        } else if idx == 0 {
                            return Err(ShellError::AccessEmptyContent { span: path_span });
                        } else {
                            return Err(ShellError::AccessBeyondEnd {
                                max_idx: idx - 1,
                                span: path_span,
                            });
                        }
                    }

                    // cannot fail since loop above does at least one iteration or returns an error
                    let value = pre_elems.last_mut().expect("one element");

                    if let Value::Closure {
                        val: closure_val, ..
                    } = replacement.clone()
                    {
                        update_single_value_by_closure(
                            value,
                            ClosureEvalOnce::new(engine_state, stack, *closure_val),
                            head,
                            &new_members,
                            true,
                        )?;
                    } else {
                        value.update_data_at_cell_path(&new_members, replacement)?;
                    }

                    return Ok(pre_elems
                        .into_iter()
                        .chain(stream)
                        .into_pipeline_data_with_metadata(
                            head,
                            engine_state.signals().clone(),
                            metadata,
                        ));
                }

            if let Some((
                &PathMember::Int {
                    val,
                    span: path_span,
                    optional,
                },
                path,
            )) = members.split_first()
            {
                let mut stream = stream.into_iter();
                let mut pre_elems = vec![];

                for idx in 0..=val {
                    if let Some(v) = stream.next() {
                        pre_elems.push(v);
                    } else if optional {
                        return Ok(pre_elems
                            .into_iter()
                            .chain(stream)
                            .into_pipeline_data_with_metadata(
                                head,
                                engine_state.signals().clone(),
                                metadata,
                            ));
                    } else if idx == 0 {
                        return Err(ShellError::AccessEmptyContent { span: path_span });
                    } else {
                        return Err(ShellError::AccessBeyondEnd {
                            max_idx: idx - 1,
                            span: path_span,
                        });
                    }
                }

                // cannot fail since loop above does at least one iteration or returns an error
                let value = pre_elems.last_mut().expect("one element");

                if let Value::Closure { val, .. } = replacement.clone() {
                    update_single_value_by_closure(
                        value,
                        ClosureEvalOnce::new(&engine_clone, &stack_clone, *val.clone()),
                        head,
                        path,
                        true,
                    )?;
                } else {
                    value.update_data_at_cell_path(path, replacement)?;
                }

                Ok(pre_elems
                    .into_iter()
                    .chain(stream)
                    .into_pipeline_data_with_metadata(
                        head,
                        engine_state.signals().clone(),
                        metadata,
                    ))
            } else {
                // generic element-by-element path update.  previously we
                // simply called `update_data_at_cell_path` which worked for
                // literal replacements but silently left closures in-place if
                // the user passed a block.  the earlier refactor that
                // optimised pipeline collapsing accidentally removed the
                // per-element closure handling, causing a stream of closures
                // to be emitted and then crash during serialization.  mirror
                // the logic used in the `PipelineData::Value` branch above so
                // closures are executed correctly for each row.
                let stream = stream.map(move |mut value| {
                    if let Value::Closure { val, .. } = replacement.clone() {
                        // a cloned replacement keeps the original untouched
                        match (members.first(), &mut value) {
                            (Some(PathMember::String { .. }), Value::List { vals, .. }) => {
                                let mut closure =
                                    ClosureEval::new(&engine_clone, &stack_clone, (*val).clone());
                                for val in vals {
                                    if let Err(e) = update_value_by_closure(
                                        val,
                                        &mut closure,
                                        head,
                                        &members,
                                        false,
                                    ) {
                                        return Value::error(e, head);
                                    }
                                }
                            }
                            (first, _) => {
                                if let Err(e) = update_single_value_by_closure(
                                    &mut value,
                                    ClosureEvalOnce::new(
                                        &engine_clone,
                                        &stack_clone,
                                        (*val).clone(),
                                    ),
                                    head,
                                    &members,
                                    matches!(first, Some(PathMember::Int { .. })),
                                ) {
                                    return Value::error(e, head);
                                }
                            }
                        }

                        value
                    } else if let Err(e) =
                            value.update_data_at_cell_path(&members, replacement.clone())
                    {
                        Value::error(e, head)
                    } else {
                        value
                    }
                });

                Ok(PipelineData::list_stream(stream, metadata))
            }
        }
        PipelineData::Empty => Err(ShellError::IncompatiblePathAccess {
            type_name: "empty pipeline".to_string(),
            span: head,
        }),
        PipelineData::ByteStream(stream, ..) => Err(ShellError::IncompatiblePathAccess {
            type_name: stream.type_().describe().into(),
            span: head,
        }),
    }
}

fn update_value_by_closure(
    value: &mut Value,
    closure: &mut ClosureEval,
    span: Span,
    cell_path: &[PathMember],
    first_path_member_int: bool,
) -> Result<(), ShellError> {
    let value_at_path = value.follow_cell_path(cell_path)?;

    // Don't run the closure for optional paths that don't exist
    let is_optional = cell_path.iter().any(|member| match member {
        PathMember::String { optional, .. } => *optional,
        PathMember::Int { optional, .. } => *optional,
    });
    if is_optional && matches!(value_at_path.as_ref(), Value::Nothing { .. }) {
        return Ok(());
    }

    let arg = if first_path_member_int {
        value_at_path.as_ref()
    } else {
        &*value
    };

    let new_value = closure
        .add_arg(arg.clone())
        .run_with_input(value_at_path.into_owned().into_pipeline_data())?
        .into_value(span)?;

    value.update_data_at_cell_path(cell_path, new_value)
}

fn update_single_value_by_closure(
    value: &mut Value,
    closure: ClosureEvalOnce,
    span: Span,
    cell_path: &[PathMember],
    first_path_member_int: bool,
) -> Result<(), ShellError> {
    let value_at_path = value.follow_cell_path(cell_path)?;

    // Don't run the closure for optional paths that don't exist
    let is_optional = cell_path.iter().any(|member| match member {
        PathMember::String { optional, .. } => *optional,
        PathMember::Int { optional, .. } => *optional,
    });
    if is_optional && matches!(value_at_path.as_ref(), Value::Nothing { .. }) {
        return Ok(());
    }

    let arg = if first_path_member_int {
        value_at_path.as_ref()
    } else {
        &*value
    };

    let new_value = closure
        .add_arg(arg.clone())
        .run_with_input(value_at_path.into_owned().into_pipeline_data())?
        .into_value(span)?;

    value.update_data_at_cell_path(cell_path, new_value)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_examples() {
        use crate::test_examples;

        test_examples(Update {})
    }
}
