//! External programs: run to completion within a limit, fail on a non-zero
//! exit with its error output.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Runs `program` with `args`, feeding `input` to its standard input, and
/// returns what it printed.
pub async fn run<P, A>(
    program: P,
    args: &[A],
    input: Option<&[u8]>,
    limit: Duration,
) -> io::Result<String>
where
    P: AsRef<OsStr>,
    A: AsRef<OsStr>,
{
    run_both(program, args, input, limit)
        .await
        .map(|(out, _)| out)
}

/// As `run`, with what it printed to its error output as well.
pub async fn run_both<P, A>(
    program: P,
    args: &[A],
    input: Option<&[u8]>,
    limit: Duration,
) -> io::Result<(String, String)>
where
    P: AsRef<OsStr>,
    A: AsRef<OsStr>,
{
    let shown = Path::new(program.as_ref()).display().to_string();
    let mut child = Command::new(program.as_ref())
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(data).await?;
    }
    let out = timeout(limit, child.wait_with_output())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{shown}: timed out")))??;
    if out.status.success() {
        Ok((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    } else {
        Err(io::Error::other(format!(
            "{shown}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}
