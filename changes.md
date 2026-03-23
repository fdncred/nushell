# Echo redirection behavior update

## Summary

This change updates Nushell's `echo` command so it behaves like `print` in normal command position (immediate visible output), while still supporting pipeline and file redirection use cases like:

- `echo somevalue | save foo`
- `echo somevalue o+e> foo`
- `def test [] { echo 1; echo 2; echo 3 }; test | save foo`

The key goal was to fix inconsistent behavior in semicolon-separated command blocks where only the final `echo` value was being redirected in some cases.

## What changed

### 1. `echo` runtime behavior (`crates/nu-cmd-lang/src/core_commands/echo.rs`)

`Echo::run` now has explicit runtime branching:

- If stdout is truly piped/value-collected (`pipe_stdout` is `Pipe`, `PipeSeparate`, or `Value`), `echo` returns pipeline data (existing value semantics).
- If this command is in a non-final semicolon pipeline where a pipe redirection was removed for the current call (`removed_pipe_stdout` is piped/value), `echo` does **not** print; instead it captures the value for later forwarding.
- Otherwise, `echo` prints/writes immediately using `stack.stdout()` behavior (`Print`/`Inherit`/`File`/`Null`) and returns empty.

This preserves:

- print-like UX in normal command position
- compatibility with redirection
- const behavior (`run_const`) unchanged

### 2. Redirection state tracking (`crates/nu-protocol/src/engine/stack_out_dest.rs`, `stack.rs`)

Added `removed_pipe_stdout` to `StackOutDest` and exposed `Stack::removed_pipe_stdout()`.

Why: during call setup, non-final semicolon pipelines can temporarily clear `pipe_stdout`, which made `echo` think it should print immediately. Tracking the removed value allows `echo` to detect it is still part of an outer piped context.

`StackIoGuard` now preserves/restores this tracking field correctly across call boundaries.

### 3. Semicolon pipeline value buffering (`crates/nu-protocol/src/engine/stack.rs`)

Added `semicolon_drained_values: Vec<Value>` to `Stack`, with:

- `push_semicolon_drained_value(value)`
- `take_semicolon_drained_values()`

Why: for non-final semicolon `echo` calls under an outer pipe, values must be retained and forwarded at block-return time instead of being printed or dropped.

### 4. Custom command return reassembly (`crates/nu-engine/src/eval_ir.rs`)

In `eval_call` for custom commands (`def` blocks):

- after evaluating the block, collect `callee_stack.take_semicolon_drained_values()`
- if buffered values exist, merge them with the block's final result
- return merged output as pipeline data

This ensures all `echo` outputs in semicolon-separated block bodies reach downstream consumers (`| save`, etc.), not just the final expression.

### 5. Robustness hardening after review (`crates/nu-engine/src/eval.rs`, `crates/nu-engine/src/eval_ir.rs`, `crates/nu-protocol/src/engine/stack_out_dest.rs`)

After a follow-up maintainability review, the implementation was further hardened to reduce fragility:

- Added a shared helper in `eval.rs`:
  - `merge_semicolon_drained_values(result, drained, fallback_span)`
- Reused that helper in both eval paths:
  - standard eval (`eval.rs`)
  - IR eval (`eval_ir.rs`)
- Ensured drained values are taken before propagation in both paths, so behavior stays consistent and easier to reason about.
- Updated stack guards to preserve and restore `removed_pipe_stdout` consistently:
  - `StackCollectValueGuard`
  - `StackCallArgGuard`

This removes duplicated merge logic and reduces risk of state leakage/inconsistency between evaluation modes.

### 6. Reduced statefulness (narrowed buffered state scope)

To reduce global mutable state and make behavior less fragile, buffered semicolon values were moved from `Stack` into `StackOutDest`:

- Removed `Stack::semicolon_drained_values` field.
- Added `StackOutDest::semicolon_drained_values`.
- Kept public stack API (`push_semicolon_drained_value`, `take_semicolon_drained_values`) but delegated internally to `out_dest`.
- Ensured child/capture stacks start with an empty semicolon buffer by introducing:
  - `StackOutDest::clone_with_empty_semicolon_values()`
  - and using it in `Stack::with_parent`, `captures_to_stack_preserve_out_dest`, and `gather_captures`.
- Updated relevant guards to preserve/restore this narrowed state correctly.

Why this is better:

- buffering state now lives alongside related redirection state
- state lifetime is more clearly tied to output-destination context
- less “ambient” mutable state on `Stack`
- reduced chance of accidental cross-scope leakage

## Why this approach

The previous approach was close but had a semantic gap:

- `pipe_stdout()` alone was not enough to detect outer piped contexts in non-final semicolon pipelines.
- That caused early `echo` calls to print to terminal instead of being forwarded.

This implementation fixes the root cause by:

1. preserving redirection intent through `removed_pipe_stdout`, and
2. deferring non-final `echo` values via stack buffering until block return.

It avoids broad behavioral changes to unrelated commands and keeps `echo` const semantics intact.

The hardening pass also directly addressed maintainability concerns:

- less duplication (single merge helper)
- clearer semantics (same behavior in IR and non-IR evaluation)
- safer guard restoration of temporary redirection state

## Tests added/updated

`crates/nu-command/tests/commands/echo.rs`:

- `echo_pipe_to_save_still_works`
- `echo_outerr_redirection_writes_file`
- `echo_def_redirects_all_values`
- `echo_def_pipe_to_save_redirects_all_values` (new regression for the reported issue)

These cover direct pipe, file redirection, and multi-line `def` behavior.

## Validation performed

Executed successfully:

- `cargo test -p nu-command --test tests commands::echo -- --nocapture`
- `cargo test -p nu-command --test tests commands::redirection -- --nocapture`
- `cargo test -p nu-cmd-lang echo -- --nocapture`
- `cargo test -p nu-command --test tests commands::semicolon -- --nocapture`
- `cargo test -p nu-command --test tests commands::print -- --nocapture`

Could not execute in this environment due permission denial:

- `nu -c "use toolkit.nu; toolkit fmt"`
- `nu -c "use toolkit.nu; toolkit clippy"`
- `cargo fmt --all -- --check`
