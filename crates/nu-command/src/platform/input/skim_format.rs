use nu_color_config::StyleComputer;
use nu_engine::{ClosureEval, command_prelude::*, eval_call};
use nu_protocol::{
    Config, Value,
    ast::Call as AstCall,
    debugger::{WithDebug, WithoutDebug},
};
use nu_table::common::{nu_value_to_string_clean, nu_value_to_string_colored};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use skim::prelude::{Cow, DisplayContext, ItemPreview, PreviewContext, SkimItem};
use std::collections::HashMap;

pub(crate) fn format_skim_item(
    value: &Value,
    config: &Config,
    style_computer: &StyleComputer,
    ansi: bool,
) -> (String, String) {
    let (plain_text, _) = nu_value_to_string_clean(value, config, style_computer);
    if ansi {
        let display = match value {
            // Preserve existing ANSI sequences for string inputs instead of repainting,
            // which can introduce reset-only sequences like `39m`.
            Value::String { val, .. } => val.clone(),
            _ => nu_value_to_string_colored(value, config, style_computer),
        };
        (display, plain_text)
    } else {
        (plain_text.clone(), plain_text)
    }
}

pub(crate) fn format_skim_item_with_closure(
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

pub(crate) fn preview_skim_item_with_closure(
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
pub(crate) struct SkimValueItem {
    pub value: Value,
    pub display: String,
    pub text: String,
    pub preview: Option<String>,
    pub index: usize,
    pub ansi: bool,
}

/// Convert a string that may contain ANSI SGR escape sequences into a ratatui
/// `Line` with corresponding styles applied to each text segment.  This allows
/// `--ansi` items to render with actual colours inside the skim TUI instead of
/// showing the raw escape codes as literal characters.
fn ansi_string_to_ratatui_line(s: &str) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut current_text = String::new();
    let mut current_style = Style::default();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '\x1b' {
            current_text.push(c);
            continue;
        }
        // Only handle CSI (ESC + '[') sequences.
        if chars.peek() != Some(&'[') {
            continue;
        }
        chars.next(); // consume '['

        let mut code = String::new();
        let terminated = loop {
            match chars.peek().copied() {
                Some('m') => {
                    chars.next();
                    break true;
                }
                Some(c) if c.is_ascii_digit() || c == ';' => {
                    code.push(c);
                    chars.next();
                }
                _ => break false,
            }
        };

        if !terminated {
            continue;
        }

        if !current_text.is_empty() {
            spans.push(Span::styled(
                std::mem::take(&mut current_text),
                current_style,
            ));
        }
        current_style = apply_ansi_sgr_code(&code, current_style);
    }

    if !current_text.is_empty() {
        spans.push(Span::styled(current_text, current_style));
    }
    Line::from(spans)
}

/// Apply a parsed ANSI SGR parameter string (e.g. `"1;31"`) to an existing
/// ratatui `Style`, returning the updated style.
fn apply_ansi_sgr_code(code: &str, base: Style) -> Style {
    if code.is_empty() || code == "0" {
        return Style::default();
    }

    let mut style = base;
    let parts: Vec<&str> = code.split(';').collect();
    let mut i = 0usize;

    while i < parts.len() {
        let n = parts[i].parse::<u8>().unwrap_or(0);
        match n {
            0 => style = Style::default(),
            1 => style = style.add_modifier(Modifier::BOLD),
            2 => style = style.add_modifier(Modifier::DIM),
            3 => style = style.add_modifier(Modifier::ITALIC),
            4 => style = style.add_modifier(Modifier::UNDERLINED),
            5 | 6 => style = style.add_modifier(Modifier::SLOW_BLINK),
            7 => style = style.add_modifier(Modifier::REVERSED),
            8 => style = style.add_modifier(Modifier::HIDDEN),
            9 => style = style.add_modifier(Modifier::CROSSED_OUT),
            22 => style = style.remove_modifier(Modifier::BOLD | Modifier::DIM),
            23 => style = style.remove_modifier(Modifier::ITALIC),
            24 => style = style.remove_modifier(Modifier::UNDERLINED),
            25 => style = style.remove_modifier(Modifier::SLOW_BLINK),
            27 => style = style.remove_modifier(Modifier::REVERSED),
            28 => style = style.remove_modifier(Modifier::HIDDEN),
            29 => style = style.remove_modifier(Modifier::CROSSED_OUT),
            30 => style = style.fg(Color::Black),
            31 => style = style.fg(Color::Red),
            32 => style = style.fg(Color::Green),
            33 => style = style.fg(Color::Yellow),
            34 => style = style.fg(Color::Blue),
            35 => style = style.fg(Color::Magenta),
            36 => style = style.fg(Color::Cyan),
            37 => style = style.fg(Color::White),
            38 if i + 1 < parts.len() => match parts[i + 1] {
                "5" if i + 2 < parts.len() => {
                    if let Ok(n) = parts[i + 2].parse::<u8>() {
                        style = style.fg(Color::Indexed(n));
                        i += 2;
                    }
                }
                "2" if i + 4 < parts.len() => {
                    let r = parts[i + 2].parse::<u8>().unwrap_or(0);
                    let g = parts[i + 3].parse::<u8>().unwrap_or(0);
                    let b = parts[i + 4].parse::<u8>().unwrap_or(0);
                    style = style.fg(Color::Rgb(r, g, b));
                    i += 4;
                }
                _ => {}
            },
            39 => style = style.fg(Color::Reset),
            40 => style = style.bg(Color::Black),
            41 => style = style.bg(Color::Red),
            42 => style = style.bg(Color::Green),
            43 => style = style.bg(Color::Yellow),
            44 => style = style.bg(Color::Blue),
            45 => style = style.bg(Color::Magenta),
            46 => style = style.bg(Color::Cyan),
            47 => style = style.bg(Color::White),
            48 if i + 1 < parts.len() => match parts[i + 1] {
                "5" if i + 2 < parts.len() => {
                    if let Ok(n) = parts[i + 2].parse::<u8>() {
                        style = style.bg(Color::Indexed(n));
                        i += 2;
                    }
                }
                "2" if i + 4 < parts.len() => {
                    let r = parts[i + 2].parse::<u8>().unwrap_or(0);
                    let g = parts[i + 3].parse::<u8>().unwrap_or(0);
                    let b = parts[i + 4].parse::<u8>().unwrap_or(0);
                    style = style.bg(Color::Rgb(r, g, b));
                    i += 4;
                }
                _ => {}
            },
            49 => style = style.bg(Color::Reset),
            90 => style = style.fg(Color::DarkGray),
            91 => style = style.fg(Color::LightRed),
            92 => style = style.fg(Color::LightGreen),
            93 => style = style.fg(Color::LightYellow),
            94 => style = style.fg(Color::LightBlue),
            95 => style = style.fg(Color::LightMagenta),
            96 => style = style.fg(Color::LightCyan),
            97 => style = style.fg(Color::Gray),
            100 => style = style.bg(Color::DarkGray),
            101 => style = style.bg(Color::LightRed),
            102 => style = style.bg(Color::LightGreen),
            103 => style = style.bg(Color::LightYellow),
            104 => style = style.bg(Color::LightBlue),
            105 => style = style.bg(Color::LightMagenta),
            106 => style = style.bg(Color::LightCyan),
            107 => style = style.bg(Color::Gray),
            _ => {}
        }
        i += 1;
    }
    style
}

impl SkimItem for SkimValueItem {
    fn text(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.text.as_str())
    }

    fn display(&self, context: DisplayContext) -> Line<'_> {
        if self.ansi {
            ansi_string_to_ratatui_line(&self.display)
        } else {
            context.to_line(Cow::Borrowed(self.display.as_str()))
        }
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
