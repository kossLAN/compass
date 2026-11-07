mod render;

use std::iter;

use super::{Family, NodeRules, run};
use crate::NetError;

#[derive(Clone, Copy)]
struct Hook {
    builtin: &'static str,
    chain: &'static str,
}

struct Table {
    name: &'static str,
    hooks: &'static [Hook],
    chains: &'static [&'static str],
}

const MESH: &str = "bunnyhop-mesh";

const INPUT: Hook = Hook {
    builtin: "INPUT",
    chain: "bunnyhop-input",
};

const FORWARD: Hook = Hook {
    builtin: "FORWARD",
    chain: "bunnyhop-forward",
};

const POSTROUTING: Hook = Hook {
    builtin: "POSTROUTING",
    chain: "bunnyhop-postrouting",
};

const FILTER: Table = Table {
    name: "filter",
    hooks: &[INPUT, FORWARD],
    chains: &[INPUT.chain, FORWARD.chain, MESH],
};

const NAT: Table = Table {
    name: "nat",
    hooks: &[POSTROUTING],
    chains: &[POSTROUTING.chain],
};

struct Jump {
    hook: Hook,
    count: usize,
    first: bool,
}

impl Jump {
    fn parse(hook: Hook, listing: &str) -> Self {
        let jump = format!("-A {} -j {}", hook.builtin, hook.chain);
        let rules: Vec<&str> = listing
            .lines()
            .filter(|line| line.starts_with("-A "))
            .collect();

        Self {
            hook,
            count: rules.iter().filter(|rule| **rule == jump).count(),
            first: rules.first().is_some_and(|rule| *rule == jump),
        }
    }

    const fn settled(&self) -> bool {
        self.first && self.count == 1
    }

    fn deletes(&self) -> impl Iterator<Item = String> {
        iter::repeat_n(
            format!("-D {} -j {}", self.hook.builtin, self.hook.chain),
            self.count,
        )
    }

    fn insert(&self) -> String {
        format!("-I {} 1 -j {}", self.hook.builtin, self.hook.chain)
    }
}

struct Jumps {
    filter: Vec<Jump>,
    nat: Vec<Jump>,
}

impl Jumps {
    async fn read(family: Family) -> Result<Self, NetError> {
        Ok(Self {
            filter: read_jumps(family, &FILTER).await?,
            nat: read_jumps(family, &NAT).await?,
        })
    }
}

impl Family {
    const fn iptables(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    const fn iptables_restore(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }
}

pub async fn available() -> Result<(), NetError> {
    for family in Family::ALL {
        run(family.iptables(), &["-w", "-S", "INPUT"], None).await?;
    }

    Ok(())
}

pub async fn apply(rules: &NodeRules) -> Result<(), NetError> {
    for family in Family::ALL {
        let jumps = Jumps::read(family).await?;
        restore(family, &render::apply(rules, family, &jumps)).await?;
    }

    Ok(())
}

pub async fn remove() -> Result<(), NetError> {
    for family in Family::ALL {
        let jumps = Jumps::read(family).await?;
        restore(family, &render::remove(&jumps)).await?;
    }

    Ok(())
}

async fn read_jumps(family: Family, table: &Table) -> Result<Vec<Jump>, NetError> {
    let mut jumps = Vec::new();

    for hook in table.hooks {
        let listing = run(
            family.iptables(),
            &["-w", "-t", table.name, "-S", hook.builtin],
            None,
        )
        .await?;
        jumps.push(Jump::parse(*hook, &listing));
    }

    Ok(jumps)
}

async fn restore(family: Family, script: &str) -> Result<(), NetError> {
    run(
        family.iptables_restore(),
        &["-w", "--noflush"],
        Some(script),
    )
    .await?;
    Ok(())
}
