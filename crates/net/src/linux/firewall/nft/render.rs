use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use compass_proto::{DNS_PORT, PacketRule, PortRange, Proto};
use ipnet::IpNet;

use super::reset;
use crate::linux::TABLE;
use crate::linux::firewall::{Family, NodeRules};

impl Family {
    const fn suffix(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    const fn set_type(self) -> &'static str {
        match self {
            Self::V4 => "ipv4_addr",
            Self::V6 => "ipv6_addr",
        }
    }

    const fn selector(self) -> &'static str {
        match self {
            Self::V4 => "ip",
            Self::V6 => "ip6",
        }
    }
}

#[derive(Clone, Copy)]
enum Hook {
    Input,
    Forward,
    Postrouting,
}

impl Hook {
    const fn declaration(self) -> &'static str {
        match self {
            Self::Input => "type filter hook input priority filter; policy accept;",
            Self::Forward => "type filter hook forward priority filter; policy accept;",
            Self::Postrouting => "type nat hook postrouting priority srcnat; policy accept;",
        }
    }
}

#[derive(Default)]
struct Table {
    sets: String,
    chains: String,
}

impl Table {
    fn set(&mut self, name: &str, family: Family, nets: &[IpNet]) -> Option<String> {
        let elements: Vec<String> = nets
            .iter()
            .filter(|net| family.matches(net))
            .map(ToString::to_string)
            .collect();

        if elements.is_empty() {
            return None;
        }

        let name = format!("{name}_{}", family.suffix());
        let _ = write!(
            self.sets,
            "\tset {name} {{\n\t\ttype {}\n\t\tflags interval\n\t\tauto-merge\n\t\telements = {{ {} }}\n\t}}\n",
            family.set_type(),
            elements.join(", "),
        );
        Some(name)
    }

    fn chain(&mut self, name: &str, hook: Option<Hook>, rules: &[String]) {
        let _ = writeln!(self.chains, "\tchain {name} {{");

        if let Some(hook) = hook {
            let _ = writeln!(self.chains, "\t\t{}", hook.declaration());
        }

        for rule in rules {
            let _ = writeln!(self.chains, "\t\t{rule}");
        }

        let _ = writeln!(self.chains, "\t}}");
    }

    fn finish(self) -> String {
        format!(
            "{}table inet {TABLE} {{\n{}{}}}\n",
            reset(),
            self.sets,
            self.chains
        )
    }
}

fn list(items: impl IntoIterator<Item = String>) -> String {
    let items: Vec<String> = items.into_iter().collect();

    match items.as_slice() {
        [single] => single.clone(),
        _ => format!("{{ {} }}", items.join(", ")),
    }
}

fn input_chain(
    interface: &str,
    prefixes: &BTreeSet<IpNet>,
    addresses: &BTreeSet<IpAddr>,
) -> Vec<String> {
    let mut rules = vec![
        "iifname \"lo\" accept".to_owned(),
        format!("iifname {interface} jump mesh"),
    ];

    for net in prefixes {
        let ip = Family::of(net.addr()).selector();
        rules.push(format!("{ip} saddr {net} drop"));
    }

    for address in addresses {
        let ip = Family::of(*address).selector();
        rules.push(format!("{ip} daddr {address} drop"));
    }

    rules
}

enum Matches {
    Everything,
    Only(String),
    Nothing,
}

fn protocol_match(protos: &[Proto], ports: &[PortRange], family: Family) -> Matches {
    let name = |proto: Proto| match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => family.icmp(),
    };

    if ports.is_empty() {
        return match protos {
            [] => Matches::Everything,
            protos => Matches::Only(format!(
                "meta l4proto {}",
                list(protos.iter().map(|proto| name(*proto).to_owned()))
            )),
        };
    }

    let with_ports: Vec<Proto> = if protos.is_empty() {
        vec![Proto::Tcp, Proto::Udp]
    } else {
        protos
            .iter()
            .copied()
            .filter(|proto| matches!(proto, Proto::Tcp | Proto::Udp))
            .collect()
    };

    let ports = list(ports.iter().map(ToString::to_string));

    match with_ports.as_slice() {
        [] => Matches::Nothing,
        [single] => Matches::Only(format!("{} dport {ports}", name(*single))),
        many => Matches::Only(format!(
            "meta l4proto {} th dport {ports}",
            list(many.iter().map(|proto| name(*proto).to_owned()))
        )),
    }
}

pub fn render(rules: &NodeRules) -> String {
    let mut table = Table::default();
    let interface = format!("\"{}\"", rules.interface);

    let mut mesh = vec!["ct state invalid drop".to_owned()];
    mesh.extend(rules.local_dns.map(|address| {
        let ip = Family::of(address).selector();
        format!("{ip} daddr {address} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} drop")
    }));
    mesh.push("ct direction reply ct state established accept".to_owned());
    mesh.push("ct state related accept".to_owned());

    for (index, rules) in rules.meshes.iter().enumerate() {
        for (rule_index, rule) in rules.inbound.iter().enumerate() {
            let name = format!("mesh{index}_rule{rule_index}");
            mesh.extend(render_packet_rule(
                &mut table,
                &name,
                &rules.addresses,
                rule,
            ));
        }
    }

    mesh.push("counter drop".to_owned());

    let exit_clients: Vec<IpNet> = rules
        .meshes
        .iter()
        .flat_map(|rules| rules.exit_clients.iter().copied())
        .collect();
    let prefixes: BTreeSet<IpNet> = rules
        .meshes
        .iter()
        .flat_map(|rules| rules.prefixes.iter().copied())
        .collect();
    let addresses: BTreeSet<IpAddr> = rules
        .meshes
        .iter()
        .flat_map(|rules| rules.addresses.iter().copied())
        .collect();
    let mut forward = Vec::new();
    let mut postrouting = Vec::new();

    for family in Family::ALL {
        if let Some(clients) = table.set("exit_clients", family, &exit_clients) {
            let ip = family.selector();
            forward.push(format!(
                "iifname {interface} {ip} saddr @{clients} oifname != {interface} accept"
            ));
            postrouting.push(format!(
                "{ip} saddr @{clients} oifname != {interface} masquerade"
            ));
        }
    }

    if !forward.is_empty() {
        forward.insert(0, "ct state established,related accept".to_owned());
    }

    forward.push(format!("iifname {interface} drop"));
    forward.push(format!("oifname {interface} drop"));

    table.chain(
        "input",
        Some(Hook::Input),
        &input_chain(&interface, &prefixes, &addresses),
    );
    table.chain("forward", Some(Hook::Forward), &forward);

    if !postrouting.is_empty() {
        table.chain("postrouting", Some(Hook::Postrouting), &postrouting);
    }

    table.chain("mesh", None, &mesh);
    table.finish()
}

fn render_packet_rule(
    table: &mut Table,
    name: &str,
    addresses: &[IpAddr],
    rule: &PacketRule,
) -> Vec<String> {
    Family::ALL
        .into_iter()
        .filter_map(|family| {
            let protocol = match protocol_match(&rule.protos, &rule.ports, family) {
                Matches::Everything => String::new(),
                Matches::Only(protocol) => format!(" {protocol}"),
                Matches::Nothing => return None,
            };

            let destinations: Vec<String> = addresses
                .iter()
                .filter(|address| family.holds(**address))
                .map(ToString::to_string)
                .collect();

            if destinations.is_empty() {
                return None;
            }

            let set = table.set(name, family, &rule.src)?;
            let ip = family.selector();
            Some(format!(
                "{ip} daddr {} {ip} saddr @{set}{protocol} accept",
                list(destinations)
            ))
        })
        .collect()
}
