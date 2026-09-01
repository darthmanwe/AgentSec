# AgentSec authorization policy (AS-009)
#
# Rego v1 syntax. OPA is pinned at 1.20.1, where `if` on every rule and `contains` on
# every multi-value rule are mandatory - policy written from pre-1.0 habits will not parse.
#
# Three structural choices, each defending a specific failure:
#
#   1. ONE decision document. `decision` is a single complete rule with an else-chain, so
#      adding a rule cannot accidentally add a new way to be allowed. A partial-set design
#      where any matching rule could contribute an allow is how policy bundles grow holes.
#
#   2. NO WILDCARDS. Every permitted tool/operation pair is enumerated. `read_only` as a
#      risk class is necessary but never sufficient - the operation must also be on the
#      list, because a tool's risk classification is metadata and metadata can be wrong.
#
#   3. DENY WINS. Precedence is hard_deny > require_approval > allow > default deny. A
#      request matching both a deny and an allow is denied.

package agentsec.authz

import rego.v1

# --------------------------------------------------------------------------- data

# Read operations permitted without approval. Enumerated per tool: there is no
# "all read operations on any tool" rule, because the next tool added would inherit it.
read_operations := {
	"fixture_repo": {"list_files", "read_file", "search_code"},
	"vuln_intel": {"lookup_package", "lookup_cve", "lookup_advisory"},
	"fake_cloud": {
		"list_resources",
		"get_resource",
		"read_iam_policy",
		"read_security_group",
		"read_bucket_policy",
	},
	"fake_jira": {"search", "read_issue"},
	"github": {"read_file", "search_code", "get_diff", "get_pull_request"},
	"semgrep": {"scan_repository", "scan_path"},
	"trivy": {"scan_filesystem", "scan_dependency_manifest", "scan_iac"},
}

# Mutating operations a human may authorise. Reaching this list is not permission; it is
# permission to *ask*. The capability is minted only after an operator approves the exact
# action digest (AS-010, AS-011).
approval_operations := {
	"fake_jira": {"create_issue", "comment"},
	"fake_cloud": {"apply_remediation"},
	"github": {"comment_pull_request"},
}

# Operations that are never permitted, by any principal, with any approval. Listed
# explicitly rather than relying on absence from the allow lists, so the intent is
# auditable and the denial produces a specific reason code rather than "default_deny".
forbidden_operations := {
	"fake_cloud": {"get_secret", "export_secret", "read_secret", "assume_role"},
	"github": {"read_secret", "create_release", "delete_branch"},
	"fake_jira": {"delete_issue"},
	"fixture_repo": {"write_file", "delete_file"},
}

# Resource schemes the system knows about. An unrecognised scheme is a misconfiguration or
# an attempt to reach somewhere unmodelled; either way it is not a thing to guess about.
known_schemes := {"fixture", "jira", "cloud", "github", "vuln"}

# Which schemes each tool may address. Without this, `fixture_repo` could be pointed at a
# `jira://` or `cloud://` resource: every individual check passes (known tool, enumerated
# read operation, known scheme) while the composition is nonsense. That is a confused
# deputy - the tool has authority for its own domain and gets aimed at another.
#
# Found by end-to-end testing against live OPA, not by the unit tests, which only ever
# paired each tool with its natural scheme.
tool_schemes := {
	"fixture_repo": {"fixture"},
	"vuln_intel": {"vuln"},
	"fake_cloud": {"cloud"},
	"fake_jira": {"jira"},
	"github": {"github"},
	# Scanners read a checked-out workspace, which may come from either source.
	"semgrep": {"fixture", "github"},
	"trivy": {"fixture", "github"},
}

known_tools := object.keys(read_operations) | object.keys(approval_operations)

# --------------------------------------------------------------------------- helpers

tool := input.action.tool

operation := input.action.operation

default is_known_tool := false

is_known_tool if tool in known_tools

default is_forbidden := false

is_forbidden if operation in forbidden_operations[tool]

default is_secret_access := false

is_secret_access if input.action.risk_class == "secret_access"

default is_known_scheme := false

is_known_scheme if input.action.resource.scheme in known_schemes

default is_scheme_bound_to_tool := false

is_scheme_bound_to_tool if input.action.resource.scheme in tool_schemes[tool]

# A read is allowed only when the operation is enumerated AND the action is classified
# read-only. Both must hold: the enumeration guards against a mislabelled risk class, and
# the risk class guards against an operation that has quietly become mutating.
default is_permitted_read := false

is_permitted_read if {
	operation in read_operations[tool]
	input.action.risk_class == "read_only"
	not input.action.is_mutating
}

default needs_approval := false

needs_approval if operation in approval_operations[tool]

# --------------------------------------------------------------------------- decision

# Precedence is expressed by the else-chain, top to bottom. Deny conditions come first so
# that a request matching both a deny and an allow is denied.
decision := {
	"outcome": "DENY",
	"reason_code": "secret_access_always_denied",
	"obligations": [],
} if {
	is_secret_access
} else := {
	"outcome": "DENY",
	"reason_code": "operation_forbidden",
	"obligations": [],
} if {
	is_forbidden
} else := {
	"outcome": "DENY",
	"reason_code": "unknown_tool",
	"obligations": [],
} if {
	not is_known_tool
} else := {
	"outcome": "DENY",
	"reason_code": "unknown_resource_scheme",
	"obligations": [],
} if {
	not is_known_scheme
} else := {
	"outcome": "DENY",
	"reason_code": "resource_scheme_not_permitted_for_tool",
	"obligations": [],
} if {
	not is_scheme_bound_to_tool
} else := {
	"outcome": "REQUIRE_APPROVAL",
	"reason_code": "mutating_operation_requires_approval",
	"obligations": [
		{"kind": "capability_ttl_seconds", "value": 60},
		{"kind": "audit_level", "value": "full"},
	],
} if {
	needs_approval
} else := {
	"outcome": "ALLOW",
	"reason_code": "read_permitted",
	"obligations": [
		{"kind": "capability_ttl_seconds", "value": 60},
		{"kind": "max_result_bytes", "value": 262144},
	],
} if {
	is_permitted_read
} else := {
	"outcome": "DENY",
	"reason_code": "default_deny",
	"obligations": [],
}
