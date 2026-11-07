use std::fmt::Write as _;
use std::net::IpAddr;

use bunnyhop_proto::{DNS_PORT, PacketRule, PortRange, Proto};
use ipnet::IpNet;

use super::{NodeRules, reset};
use crate::TABLE;

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const ALL: [Self; 2] = [Self::V4, Self::V6];

    const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    const fn matches(self, net: &IpNet) -> bool {
        matches!(
            (self, net),
            (Self::V4, IpNet::V4(_)) | (Self::V6, IpNet::V6(_))
        )
    }

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

    const fn icmp(self) -> &'static str {
        match self {
            Self::V4 => "icmp",
            Self::V6 => "ipv6-icmp",
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

fn input_chain(interface: &str, mesh: &[IpNet], addresses: &[IpAddr]) -> Vec<String> {
    let mut rules = vec![
        "iifname \"lo\" accept".to_owned(),
        format!("iifname {interface} jump mesh"),
    ];

    for net in mesh {
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

    for (index, rule) in rules.inbound.iter().enumerate() {
        mesh.extend(render_packet_rule(&mut table, index, rule));
    }

    mesh.push("counter drop".to_owned());

    let mut forward = Vec::new();
    let mut postrouting = Vec::new();

    for family in Family::ALL {
        if let Some(clients) = table.set("exit_clients", family, &rules.exit_clients) {
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
        &input_chain(&interface, &rules.mesh, &rules.addresses),
    );
    table.chain("forward", Some(Hook::Forward), &forward);

    if !postrouting.is_empty() {
        table.chain("postrouting", Some(Hook::Postrouting), &postrouting);
    }

    table.chain("mesh", None, &mesh);
    table.finish()
}

fn render_packet_rule(table: &mut Table, index: usize, rule: &PacketRule) -> Vec<String> {
    Family::ALL
        .into_iter()
        .filter_map(|family| {
            let protocol = match protocol_match(&rule.protos, &rule.ports, family) {
                Matches::Everything => String::new(),
                Matches::Only(protocol) => format!(" {protocol}"),
                Matches::Nothing => return None,
            };

            let set = table.set(&format!("rule{index}"), family, &rule.src)?;
            Some(format!(
                "{} saddr @{set}{protocol} accept",
                family.selector()
            ))
        })
        .collect()
}
