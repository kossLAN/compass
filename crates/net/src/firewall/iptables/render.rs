use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use compass_proto::{DNS_PORT, PacketRule, PortRange, Proto};
use ipnet::IpNet;

use super::{FILTER, FORWARD, INPUT, Jump, Jumps, MESH, NAT, POSTROUTING, Table};
use crate::firewall::{Family, NodeRules};

pub fn apply(rules: &NodeRules, family: Family, jumps: &Jumps) -> String {
    let mut script = String::new();
    write_table(
        &mut script,
        &FILTER,
        settle(&jumps.filter, filter(rules, family)),
    );
    write_table(&mut script, &NAT, settle(&jumps.nat, nat(rules, family)));
    script
}

pub fn remove(jumps: &Jumps) -> String {
    let mut script = String::new();
    write_table(&mut script, &FILTER, teardown(&FILTER, &jumps.filter));
    write_table(&mut script, &NAT, teardown(&NAT, &jumps.nat));
    script
}

fn settle(jumps: &[Jump], rules: Vec<String>) -> Vec<String> {
    let mut commands = Vec::new();

    for jump in jumps.iter().filter(|jump| !jump.settled()) {
        commands.extend(jump.deletes());
        commands.push(jump.insert());
    }

    commands.extend(rules);
    commands
}

fn teardown(table: &Table, jumps: &[Jump]) -> Vec<String> {
    jumps
        .iter()
        .flat_map(Jump::deletes)
        .chain(table.chains.iter().map(|chain| format!("-X {chain}")))
        .collect()
}

fn write_table(script: &mut String, table: &Table, commands: Vec<String>) {
    let _ = writeln!(script, "*{}", table.name);

    for chain in table.chains {
        let _ = writeln!(script, ":{chain} - [0:0]");
    }

    for command in commands {
        let _ = writeln!(script, "{command}");
    }

    let _ = writeln!(script, "COMMIT");
}

fn filter(rules: &NodeRules, family: Family) -> Vec<String> {
    let interface = &rules.interface;
    let input = INPUT.chain;
    let forward = FORWARD.chain;

    let prefixes: BTreeSet<IpNet> = rules
        .meshes
        .iter()
        .flat_map(|mesh| mesh.prefixes.iter().copied())
        .filter(|net| family.matches(net))
        .collect();
    let addresses: BTreeSet<IpAddr> = rules
        .meshes
        .iter()
        .flat_map(|mesh| mesh.addresses.iter().copied())
        .filter(|address| family.holds(*address))
        .collect();

    let mut commands = vec![
        format!("-A {input} -i lo -j RETURN"),
        format!("-A {input} -i {interface} -g {MESH}"),
    ];
    commands.extend(
        prefixes
            .iter()
            .map(|net| format!("-A {input} -s {net} -j DROP")),
    );
    commands.extend(
        addresses
            .iter()
            .map(|address| format!("-A {input} -d {address} -j DROP")),
    );

    commands.push(format!("-A {MESH} -m conntrack --ctstate INVALID -j DROP"));

    if let Some(address) = rules.local_dns.filter(|address| family.holds(*address)) {
        for protocol in ["tcp", "udp"] {
            commands.push(format!(
                "-A {MESH} -d {address} -p {protocol} --dport {DNS_PORT} -j DROP"
            ));
        }
    }

    commands.push(format!(
        "-A {MESH} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN"
    ));
    commands.push(format!(
        "-A {MESH} -m conntrack --ctstate RELATED -j RETURN"
    ));

    for mesh in &rules.meshes {
        for rule in &mesh.inbound {
            commands.extend(packet_rule(family, &mesh.addresses, rule));
        }
    }

    commands.push(format!("-A {MESH} -j DROP"));

    if rules
        .meshes
        .iter()
        .any(|mesh| !mesh.exit_clients.is_empty())
    {
        commands.push(format!(
            "-A {forward} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
        ));
    }

    commands.extend(exit_clients(rules, family).map(|client| {
        format!("-A {forward} -i {interface} -s {client} ! -o {interface} -j RETURN")
    }));
    commands.push(format!("-A {forward} -i {interface} -j DROP"));
    commands.push(format!("-A {forward} -o {interface} -j DROP"));
    commands
}

fn nat(rules: &NodeRules, family: Family) -> Vec<String> {
    let interface = &rules.interface;
    let postrouting = POSTROUTING.chain;

    exit_clients(rules, family)
        .map(|client| format!("-A {postrouting} -s {client} ! -o {interface} -j MASQUERADE"))
        .collect()
}

fn exit_clients(rules: &NodeRules, family: Family) -> impl Iterator<Item = &IpNet> {
    rules
        .meshes
        .iter()
        .flat_map(|mesh| &mesh.exit_clients)
        .filter(move |net| family.matches(net))
}

fn packet_rule(family: Family, addresses: &[IpAddr], rule: &PacketRule) -> Vec<String> {
    let protocols = protocol_matches(&rule.protos, &rule.ports, family);
    let mut commands = Vec::new();

    for destination in addresses.iter().filter(|address| family.holds(**address)) {
        for source in rule.src.iter().filter(|net| family.matches(net)) {
            for protocol in &protocols {
                commands.push(format!(
                    "-A {MESH} -d {destination} -s {source}{protocol} -j RETURN"
                ));
            }
        }
    }

    commands
}

fn protocol_matches(protos: &[Proto], ports: &[PortRange], family: Family) -> Vec<String> {
    let name = |proto: Proto| match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => family.icmp(),
    };

    if ports.is_empty() {
        return match protos {
            [] => vec![String::new()],
            protos => protos
                .iter()
                .map(|proto| format!(" -p {}", name(*proto)))
                .collect(),
        };
    }

    let with_ports: &[Proto] = match protos {
        [] => &[Proto::Tcp, Proto::Udp],
        protos => protos,
    };

    with_ports
        .iter()
        .filter(|proto| matches!(proto, Proto::Tcp | Proto::Udp))
        .flat_map(|proto| {
            ports
                .iter()
                .map(move |range| format!(" -p {} --dport {}", name(*proto), port(*range)))
        })
        .collect()
}

fn port(range: PortRange) -> String {
    if range.start == range.end {
        range.start.to_string()
    } else {
        format!("{}:{}", range.start, range.end)
    }
}
