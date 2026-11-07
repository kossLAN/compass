use std::io::{self, Write as _};

use crate::control::Control;
use bunnyhop_proto::{
    Addresses, ExitNodeChoice, LighthouseState, PathKind, Phase, RecordEntry, RecordState,
    StatusReport,
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

        let relay = if lighthouse.relay { ", relaying" } else { "" };
        writeln!(out, "lighthouse: {} ({state}{relay})", lighthouse.url)?;
    }

    if let Some(exit_node) = &report.exit_node {
        let state = if exit_node.active {
            "active"
        } else {
            "unavailable, internet traffic is blocked"
        };

        writeln!(out, "exit:   {} ({state})", exit_node.peer)?;
    }

    let Some(node) = &report.node else {
        return Ok(());
    };

    writeln!(out, "node:   {} ({})", node.fqdn, join(node.addresses))?;

    for endpoint in &node.observed_endpoints {
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
            format!("{} (exit)", peer.hostname)
        } else {
            peer.hostname.to_string()
        };

        writeln!(
            out,
            "{:<24} {:<34} {:<32} {}",
            name,
            join(peer.addresses),
            path,
            handshake,
        )?;
    }

    Ok(())
}

fn print_records(records: &[RecordEntry]) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{:<32} {:<6} {:<40} STATE", "NAME", "TYPE", "VALUE")?;

    for entry in records {
        let state = match entry.state {
            Some(RecordState::Accepted) => "accepted".to_owned(),
            Some(RecordState::Rejected(reason)) => format!("rejected: {reason}"),
            None => "pending".to_owned(),
        };

        writeln!(
            out,
            "{:<32} {:<6} {:<40} {}",
            entry.record.name.as_str(),
            entry.record.kind().as_str(),
            entry.record.data.to_string(),
            state,
        )?;
    }

    Ok(())
}

fn join(addresses: Addresses) -> String {
    let addresses: Vec<String> = addresses
        .iter()
        .map(|address| address.to_string())
        .collect();
    addresses.join(", ")
}
