use crate::*;

/// Lex each source file's bracket structure once.
///
/// The parser lexes the inside of every list, record, closure, block and subexpression again
/// when it parses that construct, and each of those lexes scans the bytes of everything nested
/// inside it to find its closing bracket, so a byte is scanned once per nesting level. With this
/// option the lexer first records where every bracket of a file closes in one pass, and later
/// lexes jump over nested groups instead of scanning them. The tokens, spans and errors are
/// exactly the same either way; only the time spent lexing changes.
pub static LEX_ONCE: ExperimentalOption = ExperimentalOption::new(&LexOnce);

// No documentation needed here since this type isn't public.
// The static above provides all necessary details.
struct LexOnce;

impl ExperimentalOptionMarker for LexOnce {
    const IDENTIFIER: &'static str = "lex-once";
    const DESCRIPTION: &'static str = "\
        Find where every bracket of a file closes in one pass, so that lexing nested blocks, \
        lists and records skips over their contents instead of scanning them again at every \
        nesting level.";
    const STATUS: Status = Status::OptIn;
    const SINCE: Version = (0, 116, 1);
    const ISSUE: u32 = 0;
}
