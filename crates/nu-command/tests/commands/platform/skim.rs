use std::fs;

use nu_test_support::prelude::*;
use tempfile::tempdir;

#[test]
fn input_skim_select_1_returns_matching_value() -> Result {
    test()
        .run("[alpha] | input skim 'Pick one' --select-1 --query alpha")
        .expect_value_eq("alpha")
}

#[test]
fn input_skim_index_returns_selected_index() -> Result {
    test()
        .run("[alpha] | input skim --index --select-1 --query alpha")
        .expect_value_eq(0)
}

#[test]
fn input_skim_compiles_all_named_parameters() -> Result {
    let dir = tempdir().expect("create temp dir for skim integration test");
    let preselect_file = dir.path().join("preselect.txt");
    let history_file = dir.path().join("history.txt");
    let cmd_history_file = dir.path().join("cmd-history.txt");

    fs::write(&preselect_file, "alpha\n").expect("write skim preselect fixture");

    let code = format!(
        "['alpha/src/main.rs' 'beta/src/lib.rs'] | input skim --bind {{'ctrl-j':'down'}} --multi --prompt 'pick> ' --tac --min-query-length 1 --no-sort --tiebreak [score length] --nth ['1'] --with-nth ['2'] --delimiter '/' --exact --interactive --query alpha --cmd-query beta --cmd-prompt 'cmd> ' --regex --ansi --color 'fg:blue' --margin '1,2,3,4' --no-height --no-clear --no-clear-start --height 40% --min-height 5 --preview-window right:50% --reverse --tabstop 4 --no-hscroll --no-mouse --inline-info --layout reverse-list --algo clangd --case ignore --normalize --split-match ':' --last-match --keep-right --skip-to-pattern ':' --selector '>' --multi-selector '*' --select-1 --exit-0 --sync --no-strip-ansi --highlight-line --show-cmd-error --cycle --disabled --no-info --header 'items' --header-lines 1 --wrap --scrollbar '|' --no-scrollbar --history '{}' --history-size 7 --cmd-history '{}' --cmd-history-size 8 --read0 --print0 --print-query --print-cmd --print-score --print-header --print-current --output-format '{{1}}' --filter alpha --popup 'center,50%' --pre-select-n 1 --pre-select-pat a --pre-select-items ['alpha/src/main.rs' 'beta/src/lib.rs'] --pre-select-file '{}' --pre-select {{|| $in == 'alpha/src/main.rs'}} --no-clear-if-empty --format {{ $in }} --preview {{|| 'preview'}} --cmd {{|q| $q }}",
        history_file.display(),
        cmd_history_file.display(),
        preselect_file.display(),
    );

    test().parse_and_compile(code)?;
    Ok(())
}

#[test]
fn input_skim_compiles_case_mode_switches() -> Result {
    test().parse_and_compile("[Foo] | input skim --case-sensitive --select-1 --query Foo")?;
    test().parse_and_compile("[Foo] | input skim --ignore-case --select-1 --query foo")?;
    test().parse_and_compile("[Foo] | input skim --smart-case --select-1 --query Foo")?;
    Ok(())
}

#[test]
fn input_skim_preview_closure_is_lazy() -> Result {
    test()
        .run("[good bad] | input skim --select-1 --query good --preview {|r| if $r == 'good' { 'ok' } else { error make {msg: 'preview should be lazy'} }}")
        .expect_value_eq("good")
}
