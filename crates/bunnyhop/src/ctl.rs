use std::io::{self, Write as _};

use std::net::IpAddr;

use crate::control::Control;
use bunnyhop_proto::{
    ExitNodeChoice, LighthouseState, PathKind, Phase, RecordEntry, RecordState, StatusReport,
};
use serde::Serialize;

pub async fn status(control: &Control, json: bool) -> anyhow::Result<()> {
    let report = control.status().await?;

    if json {
        print_json(&report)
    } else {
        print_status(&report)
    }
}

pub async fn set_exit_node(control: &Control, choice: ExitNodeChoice) -> anyhow::Result<()> {
    let report = control.set_exit_node(choice).await?;
    print_status(&report)
}

pub async fn dns(control: &Control, json: bool) -> anyhow::Result<()> {
    let records = control.records().await?;

    if json {
        print_json(&records)
    } else {
        print_records(&records)
    }
}

fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn print_status(report: &StatusReport) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();

    let state = match &report.phase {
        Phase::Connecting => "connecting".to_owned(),
        Phase::Running => "running".to_owned(),
        Phase::Degraded(reason) => format!("degraded: {reason}"),
        Phase::Failed(reason) => format!("failed: {reason}"),
    };

    writeln!(out, "state:  {state}")?;
    writeln!(out, "key:    {}", report.key)?;

    for lighthouse in &report.lighthouses {
        let state = match &lighthouse.state {
            LighthouseState::Connecting => "connecting".to_owned(),
            LighthouseState::Connected => "connected".to_owned(),
            LighthouseState::Unreachable(reason) => format!("unreachable: {reason}"),
            LighthouseState::Rejected(reason) => format!("rejected: {reason}"),
        };

        let mesh = lighthouse
            .mesh
            .as_ref()
            .map(|mesh| format!("{mesh}, "))
            .unwrap_or_default();
        let relay = if lighthouse.relay { ", relaying" } else { "" };
        writeln!(out, "lighthouse: {} ({mesh}{state}{relay})", lighthouse.url)?;
    }

    if let Some(exit_node) = &report.exit_node {
        let state = if exit_node.active {
            "active"
        } else {
            "unavailable, internet traffic is blocked"
        };

        writeln!(out, "exit:   {} ({state})", exit_node.peer)?;
    }

    if report.nodes.is_empty() {
        return Ok(());
    }

    for node in &report.nodes {
        writeln!(
            out,
            "node:   {} ({}){}",
            node.fqdn,
            join(&node.addresses),
            taken(&node.taken)
        )?;
    }

    for endpoint in &report.observed_endpoints {
        writeln!(out, "public: {endpoint}")?;
    }

    if report.peers.is_empty() {
        return Ok(());
    }

    writeln!(out)?;
    writeln!(
        out,
        "{:<24} {:<34} {:<32} HANDSHAKE",
        "PEER", "ADDRESSES", "PATH"
    )?;

    for peer in &report.peers {
        let path = match &peer.path {
            PathKind::Direct(endpoint) => format!("direct {endpoint}"),
            PathKind::Relay(_) if !peer.online => "offline".to_owned(),
            PathKind::Relay(lighthouse) => {
                format!("relay {}", lighthouse.host_str().unwrap_or_default())
            },
            PathKind::None => "unreachable".to_owned(),
        };

        let handshake = peer
            .last_handshake_secs
            .map_or_else(|| "-".to_owned(), |secs| format!("{secs}s ago"));

        let name = if peer.exit_node {
            format!("{} (exit)", peer.fqdn)
        } else {
            peer.fqdn.clone()
        };

        writeln!(
            out,
            "{:<24} {:<34} {:<32} {}",
            name,
            format!("{}{}", join(&peer.addresses), taken(&peer.taken)),
            path,
            handshake,
        )?;
    }

    Ok(())
}

fn print_records(records: &[RecordEntry]) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "{:<24} {:<32} {:<6} {:<40} STATE",
        "MESH", "NAME", "TYPE", "VALUE"
    )?;

    for entry in records {
        let state = match entry.state {
            Some(RecordState::Accepted) => "accepted".to_owned(),
            Some(RecordState::Rejected(reason)) => format!("rejected: {reason}"),
            None => "pending".to_owned(),
        };

        writeln!(
            out,
            "{:<24} {:<32} {:<6} {:<40} {}",
            mesh(entry),
            entry.record.owner(),
            entry.record.kind().as_str(),
            entry.record.data.to_string(),
            state,
        )?;
    }

    Ok(())
}

fn mesh(entry: &RecordEntry) -> String {
    if let Some(mesh) = &entry.mesh {
        return mesh.to_string();
    }

    entry
        .lighthouses
        .first()
        .and_then(|url| url.host_str())
        .unwrap_or("-")
        .to_owned()
}

fn join(addresses: &[IpAddr]) -> String {
    let addresses: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    addresses.join(", ")
}

fn taken(addresses: &[IpAddr]) -> String {
    if addresses.is_empty() {
        String::new()
    } else {
        format!(" [in use by another mesh: {}]", join(addresses))
    }
}
