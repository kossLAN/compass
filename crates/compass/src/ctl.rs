use std::fmt::Display;
use std::io::{self, Write};
use std::iter;
use std::net::IpAddr;

use crate::control::Control;
use compass_proto::{
    ExitNodeChoice, LighthouseState, PathKind, Phase, RecordEntry, RecordState, StatusReport,
};
use serde::Serialize;

const LABEL_WIDTH: usize = "lighthouse: ".len();
const COLUMN_GAP: &str = "  ";

pub async fn status(control: &Control, json: bool) -> anyhow::Result<()> {
    let report = control.status().await?;

    if json {
        print_json(&report)
    } else {
        print_status(&report)
    }
}

pub async fn set_exit_node(
    control: &Control,
    choice: ExitNodeChoice,
    json: bool,
) -> anyhow::Result<()> {
    let report = control.set_exit_node(choice).await?;

    if json {
        print_json(&report)
    } else {
        print_status(&report)
    }
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

fn write_field(out: &mut impl Write, label: &str, value: impl Display) -> io::Result<()> {
    let label = format!("{label}:");
    writeln!(out, "{label:<LABEL_WIDTH$}{value}")
}

fn write_table(out: &mut impl Write, header: &[&str], rows: &[Vec<String>]) -> io::Result<()> {
    let header: Vec<String> = header.iter().map(|title| (*title).to_owned()).collect();
    let mut widths: Vec<usize> = vec![0; header.len()];

    for row in iter::once(&header).chain(rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }

    for row in iter::once(&header).chain(rows) {
        let cells: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        writeln!(out, "{}", cells.join(COLUMN_GAP).trim_end())?;
    }

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

    write_field(&mut out, "state", state)?;
    write_field(&mut out, "key", report.key)?;

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
        write_field(
            &mut out,
            "lighthouse",
            format_args!("{} ({mesh}{state}{relay})", lighthouse.url),
        )?;
    }

    if let Some(exit_node) = &report.exit_node {
        let state = if exit_node.active {
            "active"
        } else {
            "unavailable, internet traffic is blocked"
        };

        write_field(
            &mut out,
            "exit",
            format_args!("{} ({state})", exit_node.peer),
        )?;
    }

    if report.nodes.is_empty() {
        return Ok(());
    }

    for node in &report.nodes {
        write_field(
            &mut out,
            "node",
            format_args!(
                "{} ({}){}",
                node.fqdn,
                join(&node.addresses),
                taken(&node.taken)
            ),
        )?;
    }

    for endpoint in &report.observed_endpoints {
        write_field(&mut out, "public", endpoint)?;
    }

    if report.peers.is_empty() {
        return Ok(());
    }

    let rows: Vec<Vec<String>> = report
        .peers
        .iter()
        .map(|peer| {
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

            vec![
                name,
                format!("{}{}", join(&peer.addresses), taken(&peer.taken)),
                path,
                handshake,
            ]
        })
        .collect();

    writeln!(out)?;
    write_table(&mut out, &["PEER", "ADDRESSES", "PATH", "HANDSHAKE"], &rows)?;
    Ok(())
}

fn print_records(records: &[RecordEntry]) -> anyhow::Result<()> {
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|entry| {
            let state = match entry.state {
                Some(RecordState::Accepted) => "accepted".to_owned(),
                Some(RecordState::Rejected(reason)) => format!("rejected: {reason}"),
                None => "pending".to_owned(),
            };

            vec![
                mesh(entry),
                entry.record.owner(),
                entry.record.kind().as_str().to_owned(),
                entry.record.data.to_string(),
                state,
            ]
        })
        .collect();

    write_table(
        &mut io::stdout().lock(),
        &["MESH", "NAME", "TYPE", "VALUE", "STATE"],
        &rows,
    )?;
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
