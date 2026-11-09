mod render;

use super::{NodeRules, run};
use crate::NetError;
use crate::linux::TABLE;

const NFT: &str = "nft";

fn reset() -> String {
    format!("table inet {TABLE}\ndelete table inet {TABLE}\n")
}

pub async fn available() -> Result<(), NetError> {
    run(NFT, &["list", "tables"], None).await?;
    Ok(())
}

pub async fn apply(rules: &NodeRules) -> Result<(), NetError> {
    run(NFT, &["-f", "-"], Some(&render::render(rules))).await?;
    Ok(())
}

pub async fn remove() -> Result<(), NetError> {
    run(NFT, &["-f", "-"], Some(&reset())).await?;
    Ok(())
}
