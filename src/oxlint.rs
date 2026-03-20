use crate::resolve::run_linter_check;
use crate::rules::{Severity, Violation};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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

pub fn resolve(file_path: &str) -> Option<PathBuf> {
    crate::resolve::try_resolve_bin("oxlint", file_path)
}

pub fn check(content: &str, file_path: &str, bin: &Path) -> Option<Vec<Violation>> {
    let output: OxlintOutput =
        run_linter_check(content, file_path, bin, &["--format", "json"], "oxlint")?;
    Some(convert_diagnostics(output, file_path))
}

fn convert_diagnostics(output: OxlintOutput, file_path: &str) -> Vec<Violation> {
    output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = Severity::from_linter_str(&d.severity);

            Violation {
                rule: format!("oxlint/{}", d.code),
                severity,
                fix: d.help.unwrap_or(d.message),
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
        assert_eq!(violations[0].fix, "Remove the debugger statement");
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
    fn help_fallback_to_message() {
        let json = r#"{"diagnostics": [{
            "message": "This is the message",
            "code": "rule",
            "severity": "error",
            "labels": []
        }]}"#;

        let violations = parse_diagnostics(json, "f");
        assert_eq!(violations[0].fix, "This is the message");
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
