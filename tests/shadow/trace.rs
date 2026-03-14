// Shared test-support module: not every including test binary uses every item.
#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::Path;

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct TraceEvent {
    pub host: String,
    pub event: String,
    pub line: usize,
    pub raw: Value,
}

pub fn parse_trace_file(host: &str, stdout_path: &Path) -> io::Result<Vec<TraceEvent>> {
    let content = fs::read_to_string(stdout_path)?;
    Ok(parse_trace_lines(host, &content))
}

pub fn parse_trace_lines(host: &str, content: &str) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let Ok(raw) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(event) = raw
            .get("fields")
            .and_then(|fields| fields.get("event"))
            .and_then(Value::as_str)
        else {
            continue;
        };

        events.push(TraceEvent {
            host: host.to_string(),
            event: event.to_string(),
            line: idx + 1,
            raw,
        });
    }
    events
}

pub fn collect_by_host(events: &[TraceEvent]) -> HashMap<String, Vec<TraceEvent>> {
    let mut by_host = HashMap::new();
    for event in events {
        by_host
            .entry(event.host.clone())
            .or_insert_with(Vec::new)
            .push(event.clone());
    }
    by_host
}

pub fn missing_events(events: &[TraceEvent], required: &[&str]) -> Vec<String> {
    let present: BTreeSet<&str> = events.iter().map(|event| event.event.as_str()).collect();
    required
        .iter()
        .filter(|event| !present.contains(**event))
        .map(|event| (*event).to_string())
        .collect()
}
