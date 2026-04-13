use crate::platform::input::skim_format::SkimValueItem;
use nu_engine::{ClosureEval, command_prelude::*, eval_call};
use nu_protocol::{
    Config, Value,
    ast::Call as AstCall,
    debugger::{WithDebug, WithoutDebug},
    engine::Closure,
};
use ratatui::text::Line;
use skim::prelude::unbounded;
use skim::prelude::{
    Cow, DefaultSkimSelector, DisplayContext, ItemPreview, PreviewContext, Selector, Sender,
    SkimItem, SkimItemReceiver,
};
use skim::reader::CommandCollector;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) struct CommandContext {
    pub engine_state: EngineState,
    pub stack: Arc<Stack>,
    pub nu_config: Arc<Config>,
    pub format: MapperFlag,
    pub preview: MapperFlag,
}

impl CommandContext {
    pub(crate) fn new(engine_state: &EngineState, stack: &Stack) -> Result<Self, ShellError> {
        Ok(Self {
            engine_state: engine_state.clone(),
            stack: Arc::new(stack.clone()),
            nu_config: stack.get_config(engine_state),
            format: MapperFlag::None,
            preview: MapperFlag::None,
        })
    }
}

#[derive(Clone)]
pub(crate) enum MapperFlag {
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
    pub(crate) fn map<'a>(&self, context: &CommandContext, value: &'a Value) -> Cow<'a, Value> {
        match self {
            MapperFlag::None => Cow::Borrowed(value),
            MapperFlag::Closure(closure) => {
                let stack = (*context.stack).clone();
                let mut eval =
                    ClosureEval::new(&context.engine_state, &stack, closure.item.clone());
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

pub(crate) struct NuItem {
    pub context: Arc<CommandContext>,
    pub value: Value,
    pub display: Line<'static>,
}

impl NuItem {
    pub(crate) fn new(context: Arc<CommandContext>, value: Value) -> Self {
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

pub(crate) struct PredicateBasedSelector {
    pub engine_state: EngineState,
    pub stack: Arc<Stack>,
    pub predicate: Spanned<Closure>,
}

impl Selector for PredicateBasedSelector {
    fn should_select(&self, _index: usize, item: &dyn SkimItem) -> bool {
        let value = if let Some(nu_item) = item.as_any().downcast_ref::<NuItem>() {
            nu_item.value.clone()
        } else if let Some(value_item) = item.as_any().downcast_ref::<SkimValueItem>() {
            value_item.value.clone()
        } else {
            return false;
        };

        let stack = (*self.stack).clone();
        let mut eval = ClosureEval::new(&self.engine_state, &stack, self.predicate.item.clone());
        let result = eval.run_with_value(value);
        match result {
            Ok(PipelineData::Value(value, _)) => value.is_true(),
            _ => false,
        }
    }
}

pub(crate) struct CombinedSelector(pub DefaultSkimSelector, pub PredicateBasedSelector);

impl Selector for CombinedSelector {
    fn should_select(&self, index: usize, item: &dyn SkimItem) -> bool {
        self.0.should_select(index, item) || self.1.should_select(index, item)
    }
}

pub(crate) struct NuCommandCollector {
    pub context: Arc<CommandContext>,
    pub closure: Spanned<Closure>,
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

        std::thread::spawn(move || {
            components_to_stop.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let stack = (*context.stack).clone();
            let mut eval = ClosureEval::new(&context.engine_state, &stack, closure.item.clone());
            let output = eval.run_with_value(Value::string(cmd, closure.span));

            match output {
                Ok(PipelineData::ByteStream(stream, _)) => {
                    let span = stream.span();
                    if let Some(lines) = stream.lines() {
                        for line in lines {
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
                    let values = output.into_iter().collect::<Vec<Value>>();
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
