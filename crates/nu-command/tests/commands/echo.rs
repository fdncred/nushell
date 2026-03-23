use nu_path::AbsolutePathBuf;
use nu_test_support::fs::file_contents;
use nu_test_support::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_test_dir(prefix: &str) -> AbsolutePathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("nu_{prefix}_{}_{}", std::process::id(), unique));
    std::fs::create_dir_all(&dir).expect("failed to create temp test dir");
    AbsolutePathBuf::try_from(dir).expect("temp dir should be absolute")
}

#[test]
fn echo_range_is_lazy() -> Result {
    test()
        .run("echo 1..10000000000 | first 3")
        .expect_value_eq([1, 2, 3])
}

#[test]
fn echo_range_handles_inclusive() -> Result {
    test()
        .run("echo 1..3 | each { |x| $x }")
        .expect_value_eq([1, 2, 3])
}

#[test]
fn echo_range_handles_exclusive() -> Result {
    test()
        .run("echo 1..<3 | each { |x| $x }")
        .expect_value_eq([1, 2])
}

#[test]
fn echo_range_handles_inclusive_down() -> Result {
    test()
        .run("echo 3..1 | each { |it| $it }")
        .expect_value_eq([3, 2, 1])
}

#[test]
fn echo_range_handles_exclusive_down() -> Result {
    test()
        .run("echo 3..<1 | each { |it| $it }")
        .expect_value_eq([3, 2])
}

#[test]
fn echo_is_const() -> Result {
    test()
        .run("const val = echo 1..3; $val | take 10") // ensure the value is no longer a range
        .expect_value_eq([1, 2, 3])
}

#[test]
fn echo_pipe_to_save_still_works() -> Result {
    let dir = temp_test_dir("echo_pipe_to_save");
    test()
        .cwd(dir)
        .run("echo somevalue | save foo.txt; open foo.txt")
        .expect_value_eq("somevalue")
}

#[test]
fn echo_outerr_redirection_writes_file() -> Result {
    let dir = temp_test_dir("echo_outerr_redirection");
    test()
        .cwd(&dir)
        .run("echo somevalue o+e> foo.txt; open foo.txt")
        .expect_value_eq("somevalue\n")?;
    assert_eq!(file_contents(dir.join("foo.txt")), "somevalue\n");
    Ok(())
}

#[test]
fn echo_def_redirects_all_values() -> Result {
    let dir = temp_test_dir("echo_def_redirects");
    test()
        .cwd(&dir)
        .run(
            "
        def test [] {
            echo 1
            echo 2
            echo 3
        }
        test o> out.txt
        open --raw out.txt
        ",
        )
        .expect_value_eq("1\n2\n3\n")
}

#[test]
fn echo_def_pipe_to_save_redirects_all_values() -> Result {
    let dir = temp_test_dir("echo_def_pipe_save");
    test()
        .cwd(&dir)
        .run(
            "
        def test [] {
            echo 1
            echo 2
            echo 3
        }
        test | save out.txt
        open --raw out.txt
        ",
        )
        .expect_value_eq("1\n2\n3\n")
}
