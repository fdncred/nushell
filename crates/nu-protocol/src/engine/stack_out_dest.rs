use crate::{OutDest, Value, engine::Stack};
use std::{
    fs::File,
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub enum Redirection {
    /// A pipe redirection.
    ///
    /// This will only affect the last command of a block.
    /// This is created by pipes and pipe redirections (`|`, `e>|`, `o+e>|`, etc.),
    /// or set by the next command in the pipeline (e.g., `ignore` sets stdout to [`OutDest::Null`]).
    Pipe(OutDest),
    /// A file redirection.
    ///
    /// This will affect all commands in the block.
    /// This is only created by file redirections (`o>`, `e>`, `o+e>`, etc.).
    File(Arc<File>),
}

impl Redirection {
    pub fn file(file: File) -> Self {
        Self::File(Arc::new(file))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StackOutDest {
    /// The stream to use for the next command's stdout.
    pub pipe_stdout: Option<OutDest>,
    /// The stream to use for the next command's stderr.
    pub pipe_stderr: Option<OutDest>,
    /// The stream used for the command stdout if `pipe_stdout` is `None`.
    ///
    /// This should only ever be `File` or `Inherit`.
    pub stdout: OutDest,
    /// The stream used for the command stderr if `pipe_stderr` is `None`.
    ///
    /// This should only ever be `File` or `Inherit`.
    pub stderr: OutDest,
    /// The previous stdout used before the current `stdout` was set.
    ///
    /// This is used only when evaluating arguments to commands,
    /// since the arguments are lazily evaluated inside each command
    /// after redirections have already been applied to the command/stack.
    ///
    /// This should only ever be `File` or `Inherit`.
    pub parent_stdout: Option<OutDest>,
    /// The previous stderr used before the current `stderr` was set.
    ///
    /// This is used only when evaluating arguments to commands,
    /// since the arguments are lazily evaluated inside each command
    /// after redirections have already been applied to the command/stack.
    ///
    /// This should only ever be `File` or `Inherit`.
    pub parent_stderr: Option<OutDest>,
    /// The previous pipe stdout removed for the current call.
    ///
    /// This lets commands detect when they are in a non-final semicolon pipeline inside a caller
    /// that requested piped stdout.
    pub removed_pipe_stdout: Option<OutDest>,
    /// Values captured from semicolon-drained pipelines for command-specific forwarding.
    ///
    /// This is transient per evaluation context and should not be propagated when creating a fresh
    /// child evaluation stack.
    pub semicolon_drained_values: Vec<Value>,
}

impl StackOutDest {
    pub(crate) fn new() -> Self {
        Self {
            pipe_stdout: Some(OutDest::Print),
            pipe_stderr: Some(OutDest::Print),
            stdout: OutDest::Inherit,
            stderr: OutDest::Inherit,
            parent_stdout: None,
            parent_stderr: None,
            removed_pipe_stdout: None,
            semicolon_drained_values: vec![],
        }
    }

    /// Returns the [`OutDest`] to use for current command's stdout.
    ///
    /// This will be the pipe redirection if one is set,
    /// otherwise it will be the current file redirection,
    /// otherwise it will be the process's stdout indicated by [`OutDest::Inherit`].
    pub(crate) fn stdout(&self) -> &OutDest {
        self.pipe_stdout.as_ref().unwrap_or(&self.stdout)
    }

    /// Returns the [`OutDest`] to use for current command's stderr.
    ///
    /// This will be the pipe redirection if one is set,
    /// otherwise it will be the current file redirection,
    /// otherwise it will be the process's stderr indicated by [`OutDest::Inherit`].
    pub(crate) fn stderr(&self) -> &OutDest {
        self.pipe_stderr.as_ref().unwrap_or(&self.stderr)
    }

    fn push_stdout(&mut self, stdout: OutDest) -> Option<OutDest> {
        let stdout = mem::replace(&mut self.stdout, stdout);
        self.parent_stdout.replace(stdout)
    }

    fn push_stderr(&mut self, stderr: OutDest) -> Option<OutDest> {
        let stderr = mem::replace(&mut self.stderr, stderr);
        self.parent_stderr.replace(stderr)
    }

    pub(crate) fn push_semicolon_drained_value(&mut self, value: Value) {
        self.semicolon_drained_values.push(value);
    }

    pub(crate) fn take_semicolon_drained_values(&mut self) -> Vec<Value> {
        mem::take(&mut self.semicolon_drained_values)
    }

    pub(crate) fn clone_with_empty_semicolon_values(&self) -> Self {
        let mut cloned = self.clone();
        cloned.semicolon_drained_values.clear();
        cloned
    }
}

pub struct StackIoGuard<'a> {
    stack: &'a mut Stack,
    old_pipe_stdout: Option<OutDest>,
    old_pipe_stderr: Option<OutDest>,
    old_parent_stdout: Option<OutDest>,
    old_parent_stderr: Option<OutDest>,
    old_removed_pipe_stdout: Option<OutDest>,
}

impl<'a> StackIoGuard<'a> {
    pub(crate) fn new(
        stack: &'a mut Stack,
        stdout: Option<Redirection>,
        stderr: Option<Redirection>,
    ) -> Self {
        let out_dest = &mut stack.out_dest;
        let old_removed_pipe_stdout = out_dest.removed_pipe_stdout.take();

        let (old_pipe_stdout, old_parent_stdout) = match stdout {
            Some(Redirection::Pipe(stdout)) => {
                let old = out_dest.pipe_stdout.replace(stdout);
                out_dest.removed_pipe_stdout = None;
                (old, out_dest.parent_stdout.take())
            }
            Some(Redirection::File(file)) => {
                let file = OutDest::from(file);
                out_dest.removed_pipe_stdout = None;
                (
                    out_dest.pipe_stdout.replace(file.clone()),
                    out_dest.push_stdout(file),
                )
            }
            None => {
                let old = out_dest.pipe_stdout.take();
                out_dest.removed_pipe_stdout = old.clone();
                (old, out_dest.parent_stdout.take())
            }
        };

        let (old_pipe_stderr, old_parent_stderr) = match stderr {
            Some(Redirection::Pipe(stderr)) => {
                let old = out_dest.pipe_stderr.replace(stderr);
                (old, out_dest.parent_stderr.take())
            }
            Some(Redirection::File(file)) => (
                out_dest.pipe_stderr.take(),
                out_dest.push_stderr(file.into()),
            ),
            None => (out_dest.pipe_stderr.take(), out_dest.parent_stderr.take()),
        };

        StackIoGuard {
            stack,
            old_pipe_stdout,
            old_parent_stdout,
            old_pipe_stderr,
            old_parent_stderr,
            old_removed_pipe_stdout,
        }
    }
}

impl Deref for StackIoGuard<'_> {
    type Target = Stack;

    fn deref(&self) -> &Self::Target {
        self.stack
    }
}

impl DerefMut for StackIoGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stack
    }
}

impl Drop for StackIoGuard<'_> {
    fn drop(&mut self) {
        self.out_dest.pipe_stdout = self.old_pipe_stdout.take();
        self.out_dest.pipe_stderr = self.old_pipe_stderr.take();

        let old_stdout = self.old_parent_stdout.take();
        if let Some(stdout) = mem::replace(&mut self.out_dest.parent_stdout, old_stdout) {
            self.out_dest.stdout = stdout;
        }

        let old_stderr = self.old_parent_stderr.take();
        if let Some(stderr) = mem::replace(&mut self.out_dest.parent_stderr, old_stderr) {
            self.out_dest.stderr = stderr;
        }
        self.out_dest.removed_pipe_stdout = self.old_removed_pipe_stdout.take();
    }
}

pub struct StackCollectValueGuard<'a> {
    stack: &'a mut Stack,
    old_pipe_stdout: Option<OutDest>,
    old_pipe_stderr: Option<OutDest>,
    old_removed_pipe_stdout: Option<OutDest>,
    old_semicolon_drained_values: Vec<Value>,
}

impl<'a> StackCollectValueGuard<'a> {
    pub(crate) fn new(stack: &'a mut Stack) -> Self {
        let old_pipe_stdout = stack.out_dest.pipe_stdout.replace(OutDest::Value);
        let old_pipe_stderr = stack.out_dest.pipe_stderr.take();
        let old_removed_pipe_stdout = stack.out_dest.removed_pipe_stdout.take();
        let old_semicolon_drained_values = stack.out_dest.take_semicolon_drained_values();
        Self {
            stack,
            old_pipe_stdout,
            old_pipe_stderr,
            old_removed_pipe_stdout,
            old_semicolon_drained_values,
        }
    }
}

impl Deref for StackCollectValueGuard<'_> {
    type Target = Stack;

    fn deref(&self) -> &Self::Target {
        &*self.stack
    }
}

impl DerefMut for StackCollectValueGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stack
    }
}

impl Drop for StackCollectValueGuard<'_> {
    fn drop(&mut self) {
        self.out_dest.pipe_stdout = self.old_pipe_stdout.take();
        self.out_dest.pipe_stderr = self.old_pipe_stderr.take();
        self.out_dest.removed_pipe_stdout = self.old_removed_pipe_stdout.take();
        self.out_dest.semicolon_drained_values = mem::take(&mut self.old_semicolon_drained_values);
    }
}

pub struct StackCallArgGuard<'a> {
    stack: &'a mut Stack,
    old_pipe_stdout: Option<OutDest>,
    old_pipe_stderr: Option<OutDest>,
    old_stdout: Option<OutDest>,
    old_stderr: Option<OutDest>,
    old_removed_pipe_stdout: Option<OutDest>,
    old_semicolon_drained_values: Vec<Value>,
}

impl<'a> StackCallArgGuard<'a> {
    pub(crate) fn new(stack: &'a mut Stack) -> Self {
        let old_pipe_stdout = stack.out_dest.pipe_stdout.replace(OutDest::Value);
        let old_pipe_stderr = stack.out_dest.pipe_stderr.take();
        let old_removed_pipe_stdout = stack.out_dest.removed_pipe_stdout.take();
        let old_semicolon_drained_values = stack.out_dest.take_semicolon_drained_values();

        let old_stdout = stack
            .out_dest
            .parent_stdout
            .take()
            .map(|stdout| mem::replace(&mut stack.out_dest.stdout, stdout));

        let old_stderr = stack
            .out_dest
            .parent_stderr
            .take()
            .map(|stderr| mem::replace(&mut stack.out_dest.stderr, stderr));

        Self {
            stack,
            old_pipe_stdout,
            old_pipe_stderr,
            old_stdout,
            old_stderr,
            old_removed_pipe_stdout,
            old_semicolon_drained_values,
        }
    }
}

impl Deref for StackCallArgGuard<'_> {
    type Target = Stack;

    fn deref(&self) -> &Self::Target {
        &*self.stack
    }
}

impl DerefMut for StackCallArgGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stack
    }
}

impl Drop for StackCallArgGuard<'_> {
    fn drop(&mut self) {
        self.out_dest.pipe_stdout = self.old_pipe_stdout.take();
        self.out_dest.pipe_stderr = self.old_pipe_stderr.take();
        self.out_dest.removed_pipe_stdout = self.old_removed_pipe_stdout.take();
        self.out_dest.semicolon_drained_values = mem::take(&mut self.old_semicolon_drained_values);
        if let Some(stdout) = self.old_stdout.take() {
            self.out_dest.push_stdout(stdout);
        }
        if let Some(stderr) = self.old_stderr.take() {
            self.out_dest.push_stderr(stderr);
        }
    }
}
