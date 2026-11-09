use std::process::Stdio;

use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::{LinkDns, NetError};

const METRIC: &str = "0";

pub async fn configure(interface: &str, dns: &LinkDns) -> Result<(), NetError> {
    let mut lines: Vec<String> = dns
        .servers
        .iter()
        .map(|server| format!("nameserver {server}"))
        .collect();

    if !dns.search.is_empty() {
        lines.push(format!("search {}", dns.search.join(" ")));
    }

    let mut config = lines.join("\n");
    config.push('\n');
    run(&["-m", METRIC, "-a", interface], Some(&config)).await
}

pub async fn remove(interface: &str) -> Result<(), NetError> {
    run(&["-f", "-d", interface], None).await
}

async fn run(args: &[&str], input: Option<&str>) -> Result<(), NetError> {
    let mut child = Command::new("resolvconf")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(NetError::ResolvconfSpawn)?;

    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(input.as_bytes())
            .await
            .map_err(NetError::ResolvconfSpawn)?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(NetError::ResolvconfSpawn)?;

    if output.status.success() {
        Ok(())
    } else {
        Err(NetError::Resolvconf(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}
