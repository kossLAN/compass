use std::collections::BTreeMap;
use std::net::IpAddr;

use bunnyhop_proto::{Addresses, CnameTarget, DnsName, DnsRecord, NetMap, RecordData, RecordState};
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, PTR};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};

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

impl Zone {
    pub fn from_netmap(netmap: &NetMap, domains: &[DnsName]) -> Self {
        let domain = &netmap.network.domain;
        let mut zone = Self {
            origins: domains
                .iter()
                .filter_map(absolute)
                .map(Into::into)
                .collect(),
            records: BTreeMap::new(),
        };

        zone.add_host(&netmap.node.hostname, netmap.node.addresses, domain);

        for status in &netmap.node.records {
            if status.state == RecordState::Accepted {
                zone.add_record(&status.record, domain);
            }
        }

        for peer in &netmap.peers {
            zone.add_host(&peer.hostname, peer.addresses, domain);

            for record in &peer.records {
                zone.add_record(record, domain);
            }
        }

        zone
    }

    fn add_host(&mut self, hostname: &DnsName, addresses: Addresses, domain: &DnsName) {
        let Some(name) = in_domain(hostname, domain) else {
            return;
        };

        for address in addresses.iter() {
            let data = match address {
                IpAddr::V4(v4) => RData::A(A(v4)),
                IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
            };

            self.insert(name.clone(), data);
            self.insert(Name::from(address), RData::PTR(PTR(name.clone())));
        }
    }

    fn add_record(&mut self, record: &DnsRecord, domain: &DnsName) {
        let Some(name) = in_domain(&record.name, domain) else {
            return;
        };

        let data = match &record.data {
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

        self.insert(name, data);
    }

    fn insert(&mut self, name: Name, data: RData) {
        let record = Record::from_rdata(name.clone(), TTL, data);
        self.records.entry(name.into()).or_default().push(record);
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
