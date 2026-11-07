use std::collections::BTreeMap;
use std::net::IpAddr;

use bunnyhop_proto::{CnameTarget, DnsName, DnsRecord, RecordData, RecordState};
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, PTR};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};

use crate::client::meshes::Mesh;

const TTL: u32 = 60;
const MAX_CNAME_CHAIN: usize = 8;

#[derive(Debug, Default)]
pub struct Zone {
    origins: Vec<LowerName>,
    records: BTreeMap<LowerName, Vec<Record>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Refused,
    NotFound,
    Found(Vec<Record>),
}

fn absolute(name: &DnsName) -> Option<Name> {
    Name::from_ascii(format!("{name}.")).ok()
}

fn in_domain(name: &DnsName, domain: &DnsName) -> Option<Name> {
    absolute(&name.join(domain).ok()?)
}

struct Builder {
    zone: Zone,
    owners: BTreeMap<LowerName, usize>,
}

impl Zone {
    pub fn from_meshes(meshes: &[Mesh], owned: &[Vec<DnsName>], origins: &[DnsName]) -> Self {
        let mut builder = Builder {
            zone: Self {
                origins: origins
                    .iter()
                    .filter_map(absolute)
                    .map(Into::into)
                    .collect(),
                records: BTreeMap::new(),
            },
            owners: BTreeMap::new(),
        };

        for (mesh, zones) in meshes.iter().zip(owned) {
            let domain = &mesh.netmap.network.domain;
            let node = &mesh.netmap.node;
            let taken = mesh.taken();

            if zones.contains(domain) {
                builder.add_host(mesh.index, &node.hostname, &mesh.addresses, domain);
            }

            for status in &node.records {
                if status.state == RecordState::Accepted {
                    builder.add_record(mesh.index, &status.record, domain, zones, &taken);
                }
            }

            for peer in &mesh.netmap.peers {
                let taken = mesh.peer_taken(peer);
                let addresses = mesh.peer_addresses(&peer.key);

                if zones.contains(domain) {
                    builder.add_host(mesh.index, &peer.hostname, addresses, domain);
                }

                for record in &peer.records {
                    builder.add_record(mesh.index, record, domain, zones, &taken);
                }
            }
        }

        builder.zone
    }

    pub fn lookup(&self, name: &LowerName, kind: RecordType) -> Answer {
        if !self.origins.iter().any(|origin| origin.zone_of(name)) {
            return Answer::Refused;
        }

        if !self.records.contains_key(name) {
            return Answer::NotFound;
        }

        let mut answers = Vec::new();
        let mut current = name.clone();

        for _ in 0..MAX_CNAME_CHAIN {
            let Some(records) = self.records.get(&current) else {
                break;
            };

            let cname = records
                .iter()
                .find(|record| record.record_type() == RecordType::CNAME);

            match cname.map(|record| &record.data) {
                Some(RData::CNAME(CNAME(target))) if kind != RecordType::CNAME => {
                    answers.extend(cname.cloned());
                    current = target.clone().into();
                },
                _ => {
                    answers.extend(
                        records
                            .iter()
                            .filter(|record| record.record_type() == kind)
                            .cloned(),
                    );
                    break;
                },
            }
        }

        Answer::Found(answers)
    }
}

impl Builder {
    fn add_host(
        &mut self,
        mesh: usize,
        hostname: &DnsName,
        addresses: &[IpAddr],
        domain: &DnsName,
    ) {
        let Some(name) = in_domain(hostname, domain) else {
            return;
        };

        for address in addresses {
            let data = match address {
                IpAddr::V4(v4) => RData::A(A(*v4)),
                IpAddr::V6(v6) => RData::AAAA(AAAA(*v6)),
            };

            self.insert(mesh, name.clone(), data);
            self.insert(mesh, Name::from(*address), RData::PTR(PTR(name.clone())));
        }
    }

    fn add_record(
        &mut self,
        mesh: usize,
        record: &DnsRecord,
        domain: &DnsName,
        zones: &[DnsName],
        taken: &[IpAddr],
    ) {
        if !zones.contains(record.zone.as_ref().unwrap_or(domain)) {
            return;
        }

        let Some(name) = record.fqdn(domain).ok().as_ref().and_then(absolute) else {
            return;
        };

        let data = match &record.data {
            RecordData::A(v4) if taken.contains(&IpAddr::V4(*v4)) => return,
            RecordData::Aaaa(v6) if taken.contains(&IpAddr::V6(*v6)) => return,
            RecordData::A(v4) => RData::A(A(*v4)),
            RecordData::Aaaa(v6) => RData::AAAA(AAAA(*v6)),
            RecordData::Cname(target) => {
                let target = match target {
                    CnameTarget::Mesh(target) => in_domain(target, domain),
                    CnameTarget::External(target) => absolute(target),
                };

                let Some(target) = target else {
                    return;
                };

                RData::CNAME(CNAME(target))
            },
        };

        self.insert(mesh, name, data);
    }

    fn insert(&mut self, mesh: usize, name: Name, data: RData) {
        let lower: LowerName = name.clone().into();

        if *self.owners.entry(lower.clone()).or_insert(mesh) != mesh {
            return;
        }

        let record = Record::from_rdata(name, TTL, data);
        self.zone.records.entry(lower).or_default().push(record);
    }
}
