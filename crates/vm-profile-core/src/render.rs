use serde::Serialize;

use crate::stats::{BlockInfo, CallInfo, CfRegion, Stats};

#[derive(Serialize)]
struct Output<'a> {
    name: &'a str,
    stats: &'a Stats,
    regions: &'a [CfRegion],
    blocks: &'a [BlockInfo],
    calls: &'a [CallInfo],
}

pub fn render_json(
    name: &str,
    stats: &Stats,
    regions: &[CfRegion],
    blocks: &[BlockInfo],
    calls: &[CallInfo],
) -> String {
    let output = Output {
        name,
        stats,
        regions,
        blocks,
        calls,
    };
    serde_json::to_string(&output).expect("JSON serialization should not fail")
}
