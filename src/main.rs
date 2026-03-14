mod biome;
mod config;
mod oxlint;
mod parse_json;
mod reporter;
mod resolve;
mod rules;
mod scanner;
mod tempfile_util;

use config::Config;
use reporter::{format_violations, format_warnings};
use rules::{non_comment_lines, Violation, RE_JS_FILE};
use std::io::{self, Read};

const MAX_INPUT_SIZE: u64 = 10_000_000; // 10MB limit

#[derive(serde::Deserialize)]
struct ToolInput {
    tool_name: String,
    tool_input: ToolInputData,
}

#[derive(serde::Deserialize)]
struct ToolInputData {
    file_path: Option<String>,
    content: Option<String>,
    new_string: Option<String>,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize)]
struct EditItem {
    new_string: Option<String>,
}

fn get_file_and_content(input: &ToolInput) -> Option<(String, String)> {
    let file_path = input.tool_input.file_path.clone()?;

    let content = match input.tool_name.as_str() {
        "Write" => input.tool_input.content.clone()?,
        "Edit" => input.tool_input.new_string.clone()?,
        "MultiEdit" => {
            let edits = input.tool_input.edits.as_ref()?;
            edits
                .iter()
                .filter_map(|e| e.new_string.clone())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => return None,
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some((file_path, content))
}

fn main() {
    let mut input_str = String::new();
    let bytes_read = match io::stdin()
        .take(MAX_INPUT_SIZE)
        .read_to_string(&mut input_str)
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("guardrails: failed to read stdin: {}", e);
            std::process::exit(1);
        }
    };

    // Fail fast on truncation - truncated JSON would produce misleading parse errors.
    if bytes_read as u64 == MAX_INPUT_SIZE {
        eprintln!(
            "guardrails: error: input too large (>={} bytes), aborting",
            MAX_INPUT_SIZE
        );
        std::process::exit(1);
    }

    let input: ToolInput = match serde_json::from_str(&input_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("guardrails: invalid JSON input: {}", e);
            std::process::exit(1);
        }
    };

    let Some((file_path, content)) = get_file_and_content(&input) else {
        eprintln!(
            "guardrails: skipping {} (unsupported or empty)",
            input.tool_name
        );
        std::process::exit(0);
    };

    let config = match Config::default().with_project_overrides(&file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrails: config error (using defaults): {}", e);
            Config::default()
        }
    };

    if !config.enabled {
        std::process::exit(0);
    }

    let mut violations: Vec<Violation> = Vec::new();

    // Priority: oxlint first (faster), biome as fallback. Only one runs per check.
    if RE_JS_FILE.is_match(&file_path) {
        if config.rules.oxlint && oxlint::is_available(&file_path) {
            violations.extend(oxlint::check(&content, &file_path));
        } else if config.rules.biome && biome::is_available(&file_path) {
            violations.extend(biome::check(&content, &file_path));
        }
    }

    let lines = non_comment_lines(&content);
    let rules = rules::load_rules(&config);
    for rule in &rules {
        if !rule.file_pattern.is_match(&file_path) {
            continue;
        }
        violations.extend(rule.check(&content, &file_path, &lines));
    }

    let blocking: Vec<&Violation> = violations
        .iter()
        .filter(|v| config.severity.block_on.contains(&v.severity))
        .collect();

    let warnings: Vec<&Violation> = violations
        .iter()
        .filter(|v| !config.severity.block_on.contains(&v.severity))
        .collect();

    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(&warnings));
    }

    if !blocking.is_empty() {
        eprintln!("{}", format_violations(&blocking));
        std::process::exit(2);
    }

    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(tool_name: &str, file_path: Option<&str>, content: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name.to_string(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: content.map(String::from),
                new_string: content.map(String::from),
                edits: None,
            },
        }
    }

    #[test]
    fn write_extracts_content() {
        let input = make_input("Write", Some("/src/app.ts"), Some("const x = 1;"));
        let (path, content) = get_file_and_content(&input).unwrap();
        assert_eq!(path, "/src/app.ts");
        assert_eq!(content, "const x = 1;");
    }

    #[test]
    fn edit_extracts_new_string() {
        let input = make_input("Edit", Some("/src/app.ts"), Some("const y = 2;"));
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "const y = 2;");
    }

    #[test]
    fn multi_edit_joins_edits() {
        let input = ToolInput {
            tool_name: "MultiEdit".to_string(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_string()),
                content: None,
                new_string: None,
                edits: Some(vec![
                    EditItem {
                        new_string: Some("line1".to_string()),
                    },
                    EditItem {
                        new_string: Some("line2".to_string()),
                    },
                ]),
            },
        };
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "line1\nline2");
    }

    #[test]
    fn unsupported_tool_returns_none() {
        let input = make_input("Bash", Some("/tmp/x"), Some("echo hi"));
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn empty_path_returns_none() {
        let input = make_input("Write", Some(""), Some("content"));
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn empty_content_returns_none() {
        let input = make_input("Write", Some("/src/app.ts"), Some(""));
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn missing_path_returns_none() {
        let input = make_input("Write", None, Some("content"));
        assert!(get_file_and_content(&input).is_none());
    }
}
