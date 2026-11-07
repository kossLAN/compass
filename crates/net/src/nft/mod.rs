mod render;

use std::net::IpAddr;
use std::process::Stdio;

use bunnyhop_proto::PacketRule;
use ipnet::IpNet;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::{NetError, TABLE};

pub use render::render;

fn reset() -> String {
    format!("table inet {TABLE}\ndelete table inet {TABLE}\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRules {
    pub interface: String,
    pub meshes: Vec<MeshRules>,
    pub local_dns: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRules {
    pub prefixes: Vec<IpNet>,
    pub addresses: Vec<IpAddr>,
    pub inbound: Vec<PacketRule>,
    pub exit_clients: Vec<IpNet>,
}

pub async fn apply(rules: &NodeRules) -> Result<(), NetError> {
    run_nft(&render(rules)).await
}

pub async fn remove() -> Result<(), NetError> {
    run_nft(&reset()).await
}

pub async fn available() -> bool {
    let status = Command::new("nft")
        .args(["list", "tables"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await;
    status.is_ok_and(|status| status.success())
}

async fn run_nft(script: &str) -> Result<(), NetError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(NetError::NftSpawn)?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(NetError::NftSpawn)?;
    }

    let output = child.wait_with_output().await.map_err(NetError::NftSpawn)?;

    if output.status.success() {
        Ok(())
    } else {
        Err(NetError::Nft(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}
