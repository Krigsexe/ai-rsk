// AST-based filter for regex matches.
// Uses tree-sitter to parse source files and determine if a regex match
// falls inside a comment or docstring.
// This eliminates false positives from regex matching inside non-code contexts.
//
// Supported languages: Python (.py), JavaScript (.js, .mjs, .cjs, .jsx),
// TypeScript (.ts, .tsx) via JavaScript grammar (comments share the same structure).

use std::ops::Range;

/// Determine the tree-sitter language for a file based on its extension.
/// Returns None for unsupported extensions (regex-only scanning applies).
fn language_for_extension(ext: &str) -> Option<tree_sitter::Language> {
    match ext {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => {
            Some(tree_sitter_javascript::LANGUAGE.into())
        }
        _ => None,
    }
}

/// Collect all byte ranges of comments and docstrings in the AST.
/// These are the regions where regex matches should be ignored.
///
/// IMPORTANT: We only filter comments and Python docstrings, NOT regular string literals.
/// String literals in code (like 'Bearer ', 'token', localStorage keys) ARE real code
/// and contain the security patterns we want to detect.
///
/// Python docstrings are identified as: a `string` node inside an `expression_statement`
/// that is the first child of a module, class body, or function body.
fn collect_non_code_ranges(node: tree_sitter::Node, ranges: &mut Vec<Range<usize>>) {
    let kind = node.kind();

    // Comments: always filtered (Python #, JS //, JS /* */)
    if kind == "comment" {
        ranges.push(node.start_byte()..node.end_byte());
        return;
    }

    // Python docstrings: a string inside expression_statement as first child of a block/module
    if kind == "expression_statement" {
        if let Some(child) = node.child(0) {
            if child.kind() == "string" {
                // Check if this expression_statement is the first statement in its parent
                if let Some(parent) = node.parent() {
                    let parent_kind = parent.kind();
                    if parent_kind == "module" || parent_kind == "block" {
                        // It's a docstring — filter it
                        ranges.push(node.start_byte()..node.end_byte());
                        return;
                    }
                }
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_non_code_ranges(child, ranges);
        }
    }
}

/// Parse a source file and return the byte ranges of all comments and strings.
/// Returns None if the file extension is not supported by tree-sitter.
/// The result is cached per file content (the caller is responsible for caching).
pub fn get_non_code_ranges(content: &str, file_extension: &str) -> Option<Vec<Range<usize>>> {
    let language = language_for_extension(file_extension)?;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;

    let tree = parser.parse(content, None)?;
    let mut ranges = Vec::new();
    collect_non_code_ranges(tree.root_node(), &mut ranges);

    Some(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_in_ranges(byte_offset: usize, ranges: &[Range<usize>]) -> bool {
        ranges.iter().any(|r| r.contains(&byte_offset))
    }

    #[test]
    fn test_python_comment_detected() {
        let code = "# DEBUG = True\nx = 1\n";
        let ranges = get_non_code_ranges(code, "py").unwrap();
        // "# DEBUG = True" starts at byte 0
        assert!(is_in_ranges(0, &ranges));
        assert!(is_in_ranges(5, &ranges)); // Inside the comment
    }

    #[test]
    fn test_python_real_code_not_filtered() {
        let code = "# comment\nDEBUG = True\n";
        let ranges = get_non_code_ranges(code, "py").unwrap();
        // "DEBUG = True" starts at byte 10
        assert!(!is_in_ranges(10, &ranges));
        assert!(!is_in_ranges(15, &ranges));
    }

    #[test]
    fn test_python_docstring_detected() {
        let code = "\"\"\"DEBUG = True\"\"\"\nx = 1\n";
        let ranges = get_non_code_ranges(code, "py").unwrap();
        // The docstring occupies bytes 0..18
        assert!(is_in_ranges(3, &ranges)); // Inside the docstring content
        assert!(is_in_ranges(10, &ranges)); // "DEBUG" inside docstring
    }

    #[test]
    fn test_python_function_docstring_detected() {
        let code = "def hello():\n    \"\"\"SECRET_KEY = 'test'\"\"\"\n    x = 1\n";
        let ranges = get_non_code_ranges(code, "py").unwrap();
        // The docstring is inside the function
        let docstring_start = code.find("\"\"\"SECRET").unwrap();
        assert!(is_in_ranges(docstring_start + 5, &ranges));
    }

    #[test]
    fn test_python_string_literal_not_filtered() {
        // Regular string literals in code are NOT filtered — they contain real patterns
        let code = "x = 'DEBUG = True'\ny = 1\n";
        let ranges = get_non_code_ranges(code, "py").unwrap();
        let string_start = code.find("'DEBUG").unwrap();
        assert!(!is_in_ranges(string_start + 1, &ranges)); // String literals are real code
    }

    #[test]
    fn test_js_comment_detected() {
        let code = "// eval(something)\nconst x = 1;\n";
        let ranges = get_non_code_ranges(code, "js").unwrap();
        assert!(is_in_ranges(3, &ranges)); // Inside the comment
    }

    #[test]
    fn test_js_multiline_comment_detected() {
        let code = "/* localStorage.setItem('token', t) */\nconst x = 1;\n";
        let ranges = get_non_code_ranges(code, "js").unwrap();
        assert!(is_in_ranges(5, &ranges)); // Inside the block comment
    }

    #[test]
    fn test_js_string_not_filtered() {
        // JS string literals are NOT filtered — they are real code
        let code = "const msg = \"localStorage.setItem('token', t)\";\n";
        let ranges = get_non_code_ranges(code, "js").unwrap();
        let string_start = code.find("\"localStorage").unwrap();
        assert!(!is_in_ranges(string_start + 1, &ranges)); // String literals are real code
    }

    #[test]
    fn test_js_real_code_not_filtered() {
        let code = "// comment\nlocalStorage.setItem('token', t);\n";
        let ranges = get_non_code_ranges(code, "js").unwrap();
        let code_start = code.find("localStorage").unwrap();
        assert!(!is_in_ranges(code_start, &ranges));
    }

    #[test]
    fn test_unsupported_extension_returns_none() {
        let code = "# comment\n";
        assert!(get_non_code_ranges(code, "html").is_none());
        assert!(get_non_code_ranges(code, "yaml").is_none());
        assert!(get_non_code_ranges(code, "md").is_none());
    }

    #[test]
    fn test_unsupported_extension_never_filters() {
        assert!(get_non_code_ranges("anything", "html").is_none());
        assert!(get_non_code_ranges("anything", "rs").is_none());
    }

    #[test]
    fn test_typescript_uses_js_grammar() {
        let code = "// comment\nconst x: number = 1;\n";
        let ranges = get_non_code_ranges(code, "ts").unwrap();
        assert!(is_in_ranges(3, &ranges)); // Inside the comment
    }

    #[test]
    fn test_tsx_uses_js_grammar() {
        let code = "// comment\nconst App = () => <div/>;\n";
        let ranges = get_non_code_ranges(code, "tsx").unwrap();
        assert!(is_in_ranges(3, &ranges));
    }
}
