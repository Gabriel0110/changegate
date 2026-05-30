#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-docs/rules}"
mkdir -p "${out_dir}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

go run ./cmd/changegate --format json rules list > "${tmp}/rules.json"

jq -r '.result[] | select(.status == "stable") | .id' "${tmp}/rules.json" | while read -r rule_id; do
  go run ./cmd/changegate --format json rules describe "${rule_id}" > "${tmp}/${rule_id}.json"
  jq -r '
    .result as $r |
    "# " + $r.title + "\n\n" +
    "| Field | Value |\n| --- | --- |\n" +
    "| Rule ID | `" + $r.id + "` |\n" +
    "| Category | `" + $r.category + "` |\n" +
    "| Severity | `" + $r.severity + "` |\n" +
    "| Confidence | `" + $r.confidence + "` |\n" +
    "| Status | `" + $r.status + "` |\n" +
    "| Version | `" + $r.version + "` |\n" +
    "| Policy pack | `" + ($r.policy_pack // "") + "` |\n\n" +
    "## What It Detects\n\n" +
    $r.description + "\n\n" +
    "## Resources\n\n" +
    (($r.resources // []) | map("- `" + . + "`") | join("\n")) + "\n\n" +
    "## Why It Matters\n\n" +
    (($r.documentation.rationale // "Review the planned infrastructure change before apply.") + "\n\n") +
    "## Remediation\n\n" +
    (($r.documentation.remediation // []) | if length == 0 then "- Review the planned infrastructure change before apply." else map("- " + .) | join("\n") end) + "\n\n" +
    "## References\n\n" +
    (($r.documentation.references // []) | if length == 0 then "- No external references." else map("- " + .) | join("\n") end) + "\n"
  ' "${tmp}/${rule_id}.json" > "${out_dir}/${rule_id}.md"
done

{
  echo "# Rule Reference"
  echo
  echo "Generated from built-in stable rule metadata."
  echo
  echo "| Rule | Category | Severity | Confidence |"
  echo "| --- | --- | --- | --- |"
  jq -r '.result[] | select(.status == "stable") | "| [`" + .id + "`](" + .id + ".md) | `" + .category + "` | `" + .severity + "` | `" + .confidence + "` |"' "${tmp}/rules.json"
} > "${out_dir}/README.md"
