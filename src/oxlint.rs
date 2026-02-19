use crate::rules::{Severity, Violation};
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::Builder;

#[derive(Debug, Deserialize)]
struct OxlintOutput {
    diagnostics: Vec<OxlintDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct OxlintDiagnostic {
    message: String,
    code: String,
    severity: String,
    help: Option<String>,
    #[serde(default)]
    labels: Vec<OxlintLabel>,
}

#[derive(Debug, Deserialize)]
struct OxlintLabel {
    span: OxlintSpan,
}

#[derive(Debug, Deserialize)]
struct OxlintSpan {
    line: u32,
}

pub fn is_available() -> bool {
    Command::new("oxlint")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Creates temp file in same directory as file_path to inherit project's oxlint config.
pub fn check(content: &str, file_path: &str) -> Vec<Violation> {
    let path = Path::new(file_path);
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");

    let temp_dir = std::env::temp_dir();
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && p.is_dir())
        .unwrap_or(&temp_dir);

    let temp_file = match Builder::new()
        .suffix(&format!(".{}", extension))
        .tempfile_in(dir)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("guardrails: oxlint: failed to create temp file: {}", e);
            return vec![];
        }
    };

    if let Err(e) = temp_file.as_file().write_all(content.as_bytes()) {
        eprintln!("guardrails: oxlint: failed to write temp file: {}", e);
        return vec![];
    }

    if let Err(e) = temp_file.as_file().flush() {
        eprintln!(
            "guardrails: oxlint: failed to flush temp file before lint: {}",
            e
        );
        return vec![];
    }

    let temp_path_str = match temp_file.path().to_str() {
        Some(s) => s,
        None => {
            eprintln!("guardrails: oxlint: temp path contains non-UTF8 characters");
            return vec![];
        }
    };

    let output = match Command::new("oxlint")
        .args(["--format", "json", temp_path_str])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("guardrails: oxlint: failed to execute: {}", e);
            return vec![];
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    match serde_json::from_str::<OxlintOutput>(&stdout) {
        Ok(o) => convert_diagnostics(o, file_path),
        Err(_) => {
            let json_str = stdout
                .lines()
                .find(|line| line.trim_start().starts_with('{'))
                .unwrap_or("");

            if json_str.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stdout.is_empty() || !stderr.is_empty() {
                    eprintln!("guardrails: oxlint: no JSON in output (may have config issues)");
                    if !stderr.is_empty() {
                        eprintln!(
                            "guardrails: oxlint stderr: {}",
                            stderr.lines().next().unwrap_or("")
                        );
                    }
                }
                return vec![];
            }

            match serde_json::from_str::<OxlintOutput>(json_str) {
                Ok(o) => convert_diagnostics(o, file_path),
                Err(e) => {
                    eprintln!("guardrails: oxlint: JSON parse error: {}", e);
                    vec![]
                }
            }
        }
    }
}

fn convert_diagnostics(output: OxlintOutput, file_path: &str) -> Vec<Violation> {
    output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = match d.severity.as_str() {
                "error" => Severity::High,
                "warning" => Severity::Medium,
                _ => Severity::Low,
            };

            Violation {
                rule: format!("oxlint/{}", d.code),
                severity,
                failure: d.help.unwrap_or(d.message),
                file: file_path.to_string(),
                line: d.labels.first().map(|l| l.span.line),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_diagnostics(json: &str, file_path: &str) -> Vec<Violation> {
        let output: OxlintOutput = serde_json::from_str(json).unwrap();
        convert_diagnostics(output, file_path)
    }

    #[test]
    fn parse_single_diagnostic() {
        let json = r#"{
            "diagnostics": [{
                "message": "`debugger` statement is not allowed",
                "code": "eslint(no-debugger)",
                "severity": "error",
                "causes": [],
                "url": "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-debugger.html",
                "help": "Remove the debugger statement",
                "filename": "test.js",
                "labels": [{"span": {"offset": 38, "length": 9, "line": 5, "column": 1}}],
                "related": []
            }],
            "number_of_files": 1,
            "number_of_rules": 2,
            "threads_count": 1,
            "start_time": 0.018
        }"#;

        let violations = parse_diagnostics(json, "test.js");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "oxlint/eslint(no-debugger)");
        assert_eq!(violations[0].severity, Severity::High);
        assert_eq!(violations[0].failure, "Remove the debugger statement");
        assert_eq!(violations[0].line, Some(5));
        assert_eq!(violations[0].file, "test.js");
    }

    #[test]
    fn parse_empty_diagnostics() {
        let json = r#"{"diagnostics": [], "number_of_files": 0, "number_of_rules": 0}"#;
        let violations = parse_diagnostics(json, "test.js");
        assert!(violations.is_empty());
    }

    #[test]
    fn severity_mapping() {
        let make_json = |severity: &str| {
            format!(
                r#"{{"diagnostics": [{{
                    "message": "msg",
                    "code": "rule",
                    "severity": "{}",
                    "labels": []
                }}]}}"#,
                severity
            )
        };

        let high = parse_diagnostics(&make_json("error"), "f");
        assert_eq!(high[0].severity, Severity::High);

        let medium = parse_diagnostics(&make_json("warning"), "f");
        assert_eq!(medium[0].severity, Severity::Medium);

        let low = parse_diagnostics(&make_json("info"), "f");
        assert_eq!(low[0].severity, Severity::Low);
    }

    #[test]
    fn help_fallback_to_message() {
        let json = r#"{"diagnostics": [{
            "message": "This is the message",
            "code": "rule",
            "severity": "error",
            "labels": []
        }]}"#;

        let violations = parse_diagnostics(json, "f");
        assert_eq!(violations[0].failure, "This is the message");
    }

    #[test]
    fn no_labels_gives_none_line() {
        let json = r#"{"diagnostics": [{
            "message": "msg",
            "code": "rule",
            "severity": "error",
            "labels": []
        }]}"#;

        let violations = parse_diagnostics(json, "f");
        assert_eq!(violations[0].line, None);
    }
}
