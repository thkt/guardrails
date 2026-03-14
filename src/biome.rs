use crate::parse_json::parse_linter_json;
use crate::resolve::{resolve_bin, run_with_timeout};
use crate::rules::{Severity, Violation};
use crate::scanner::{build_line_offsets, offset_to_line};
use crate::tempfile_util::write_temp;
use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct BiomeOutput {
    diagnostics: Vec<BiomeDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct BiomeDiagnostic {
    category: String,
    severity: String,
    description: String,
    advices: BiomeAdvices,
    location: BiomeLocation,
}

#[derive(Debug, Deserialize)]
struct BiomeAdvices {
    advices: Vec<BiomeAdvice>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BiomeAdvice {
    Log {
        log: (String, Vec<BiomeMessagePart>),
    },
    #[allow(dead_code)]
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct BiomeMessagePart {
    content: String,
}

#[derive(Debug, Deserialize)]
struct BiomeLocation {
    span: Option<Vec<u32>>,
}

pub fn is_available(file_path: &str) -> bool {
    crate::resolve::is_tool_available("biome", file_path)
}

/// Fail-open: returns empty violations on any error.
pub fn check(content: &str, file_path: &str) -> Vec<Violation> {
    let temp_file = match write_temp(content, file_path, "biome") {
        Some(f) => f,
        None => return vec![],
    };

    let temp_path_str = match temp_file.path().to_str() {
        Some(s) => s,
        None => {
            eprintln!("guardrails: biome: temp path contains non-UTF8 characters");
            return vec![];
        }
    };

    let output = match run_with_timeout(
        Command::new(resolve_bin("biome", file_path)).args([
            "lint",
            "--reporter=json",
            temp_path_str,
        ]),
        "biome",
    ) {
        Some(o) => o,
        None => return vec![],
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    match parse_linter_json::<BiomeOutput>(&stdout, &stderr, "biome") {
        Some(o) => convert_diagnostics(o, content, file_path),
        None => vec![],
    }
}

fn convert_diagnostics(output: BiomeOutput, content: &str, file_path: &str) -> Vec<Violation> {
    let line_offsets = build_line_offsets(content);

    output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = Severity::from_linter_str(&d.severity);

            let line = d.location.span.as_ref().map(|span| {
                let offset = span.first().copied().unwrap_or(0) as usize;
                offset_to_line(&line_offsets, offset) as u32
            });

            let fix = get_fix_for_rule(&d.category)
                .map(String::from)
                .unwrap_or_else(|| extract_fix_from_advices(&d.advices, &d.description));

            Violation {
                rule: format!("biome/{}", d.category),
                severity,
                fix,
                file: file_path.to_string(),
                line,
            }
        })
        .collect()
}

fn get_fix_for_rule(category: &str) -> Option<&'static str> {
    match category {
        "lint/security/noGlobalEval" => {
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        }
        "lint/suspicious/noExplicitAny" => {
            Some("Use `unknown` with type guards, or define a specific type/interface")
        }
        "lint/suspicious/noDebugger" => Some("Remove debugger statement"),
        "lint/suspicious/noConsole" => Some("Remove console.log or use a proper logger"),
        "lint/correctness/noUnusedVariables" => {
            Some("Remove the variable, or prefix with _ if intentional")
        }
        "lint/correctness/noUnusedImports" => Some("Remove the unused import"),
        "lint/a11y/useAltText" => Some("Add alt attribute to img element"),
        "lint/a11y/useButtonType" => Some("Add type attribute to button element"),
        "lint/a11y/noBlankTarget" => {
            Some("Add rel=\"noopener noreferrer\" to links with target=\"_blank\"")
        }
        _ => None,
    }
}

fn extract_fix_from_advices(advices: &BiomeAdvices, fallback: &str) -> String {
    let texts: Vec<String> = advices
        .advices
        .iter()
        .filter_map(|advice| match advice {
            BiomeAdvice::Log { log: (_, parts) } => {
                let text: String = parts.iter().map(|p| p.content.as_str()).collect();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            }
            BiomeAdvice::Other(_) => None,
        })
        .collect();

    if texts.is_empty() {
        fallback.to_string()
    } else {
        texts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_fix_for_known_rule() {
        assert_eq!(
            get_fix_for_rule("lint/security/noGlobalEval"),
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        );
        assert_eq!(
            get_fix_for_rule("lint/suspicious/noExplicitAny"),
            Some("Use `unknown` with type guards, or define a specific type/interface")
        );
        assert_eq!(
            get_fix_for_rule("lint/a11y/useAltText"),
            Some("Add alt attribute to img element")
        );
    }

    #[test]
    fn get_fix_for_unknown_rule() {
        assert!(get_fix_for_rule("unknown/rule").is_none());
    }

    #[test]
    fn extract_fix_from_empty_advices() {
        let advices = BiomeAdvices { advices: vec![] };
        let result = extract_fix_from_advices(&advices, "fallback message");
        assert_eq!(result, "fallback message");
    }

    #[test]
    fn extract_fix_from_log_advice() {
        let advices = BiomeAdvices {
            advices: vec![BiomeAdvice::Log {
                log: (
                    "info".to_string(),
                    vec![BiomeMessagePart {
                        content: "Fix suggestion".to_string(),
                    }],
                ),
            }],
        };
        let result = extract_fix_from_advices(&advices, "fallback");
        assert_eq!(result, "Fix suggestion");
    }
}
