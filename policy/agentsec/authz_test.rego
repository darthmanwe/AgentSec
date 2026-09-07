# Tests for the AgentSec authorization policy (AS-009).
#
# The negative cases matter more than the positive ones. A policy that allows the right
# things but also allows one wrong thing is worse than useless, and the wrong thing is
# never the case somebody remembered to test.

package agentsec.authz_test

import data.agentsec.authz
import rego.v1

# --------------------------------------------------------------------------- helpers

request(tool, operation, risk, scheme) := {"action": {
	"tool": tool,
	"operation": operation,
	"risk_class": risk,
	"is_mutating": risk != "read_only",
	"resource": {"scheme": scheme, "identifier": "x"},
	"qualified_name": sprintf("%s.%s", [tool, operation]),
	"argument_keys": [],
	"has_preconditions": false,
}}

read_request(tool, operation) := request(tool, operation, "read_only", "fixture")

# Same shape, with control over the resource identifier - the field the secret-path rule
# actually reads.
path_request(identifier) := {"action": {
	"tool": "fixture_repo",
	"operation": "read_file",
	"risk_class": "read_only",
	"is_mutating": false,
	"resource": {"scheme": "fixture", "identifier": identifier},
	"qualified_name": "fixture_repo.read_file",
	"argument_keys": ["path"],
	"has_preconditions": false,
}}

# ------------------------------------------------------------------- secret-bearing paths
#
# Found by the AS-028B adversarial suite. The registry classifies risk per *operation*, so
# fixture_repo.read_file is read_only whether it points at README.md or at .env - which
# meant an agent assigned a repository could read every credential in it through an
# entirely ordinary read, inside its own scope, with no other control objecting.

test_reading_a_dotenv_file_is_denied if {
	d := authz.decision with input as path_request("repo-a/.env")
	d.outcome == "DENY"
	d.reason_code == "secret_bearing_path_denied"
}

test_reading_a_private_key_is_denied if {
	d := authz.decision with input as path_request("repo-a/deploy/id_rsa")
	d.outcome == "DENY"
}

test_reading_a_pem_file_is_denied if {
	d := authz.decision with input as path_request("repo-a/certs/server.pem")
	d.outcome == "DENY"
}

test_reading_aws_credentials_is_denied if {
	d := authz.decision with input as path_request("repo-a/.aws/credentials")
	d.outcome == "DENY"
}

test_case_does_not_bypass_the_secret_path_rule if {
	d := authz.decision with input as path_request("repo-a/.ENV")
	d.outcome == "DENY"
}

test_a_traversal_toward_a_secret_is_denied if {
	d := authz.decision with input as path_request("repo-a/../../.env")
	d.outcome == "DENY"
}

# The other direction, which is the one that makes the rule usable rather than a blanket
# refusal: ordinary source files must still be readable.
test_an_ordinary_source_file_is_still_allowed if {
	d := authz.decision with input as path_request("repo-a/src/main.py")
	d.outcome == "ALLOW"
}

test_a_readme_is_still_allowed if {
	d := authz.decision with input as path_request("repo-a/README.md")
	d.outcome == "ALLOW"
}

test_a_filename_merely_mentioning_environment_is_allowed if {
	d := authz.decision with input as path_request("repo-a/docs/environment-setup.md")
	d.outcome == "ALLOW"
}

# --------------------------------------------------------------------------- allow

test_repository_read_is_allowed if {
	d := authz.decision with input as read_request("fixture_repo", "read_file")
	d.outcome == "ALLOW"
	d.reason_code == "read_permitted"
}

test_vulnerability_lookup_is_allowed if {
	d := authz.decision with input as request("vuln_intel", "lookup_cve", "read_only", "vuln")
	d.outcome == "ALLOW"
}

# Regression guards for the confused-deputy gap found by end-to-end testing: every
# individual check passed (known tool, enumerated read operation, known scheme) while the
# composition was nonsense.
test_tool_cannot_address_another_tools_scheme if {
	d := authz.decision with input as request("fixture_repo", "read_file", "read_only", "vuln")
	d.outcome == "DENY"
	d.reason_code == "resource_scheme_not_permitted_for_tool"
}

test_jira_tool_cannot_address_cloud_resources if {
	d := authz.decision with input as request("fake_jira", "read_issue", "read_only", "cloud")
	d.outcome == "DENY"
	d.reason_code == "resource_scheme_not_permitted_for_tool"
}

test_approval_path_also_enforces_scheme_binding if {
	d := authz.decision with input as request("fake_jira", "create_issue", "high_risk_write", "cloud")
	d.outcome == "DENY"
	d.reason_code == "resource_scheme_not_permitted_for_tool"
}

test_scanner_may_read_either_workspace_source if {
	a := authz.decision with input as request("semgrep", "scan_repository", "read_only", "fixture")
	b := authz.decision with input as request("trivy", "scan_filesystem", "read_only", "github")
	a.outcome == "ALLOW"
	b.outcome == "ALLOW"
}

# Every tool that can be permitted must declare which schemes it may address, or a new
# tool would silently inherit access to every scheme.
test_every_permitted_tool_declares_its_schemes if {
	every tool in authz.known_tools {
		count(object.get(authz.tool_schemes, tool, set())) > 0
	}
}

test_scanner_read_is_allowed if {
	d := authz.decision with input as read_request("semgrep", "scan_repository")
	d.outcome == "ALLOW"
}

test_allow_carries_a_result_size_obligation if {
	d := authz.decision with input as read_request("fixture_repo", "read_file")
	some obligation in d.obligations
	obligation.kind == "max_result_bytes"
}

# --------------------------------------------------------------------------- approval

test_jira_write_requires_approval if {
	d := authz.decision with input as request("fake_jira", "create_issue", "high_risk_write", "jira")
	d.outcome == "REQUIRE_APPROVAL"
	d.reason_code == "mutating_operation_requires_approval"
}

test_pr_comment_requires_approval if {
	d := authz.decision with input as request(
		"github", "comment_pull_request", "high_risk_write", "github",
	)
	d.outcome == "REQUIRE_APPROVAL"
}

test_cloud_mutation_requires_approval if {
	d := authz.decision with input as request(
		"fake_cloud", "apply_remediation", "irreversible", "cloud",
	)
	d.outcome == "REQUIRE_APPROVAL"
}

test_approval_carries_a_bounded_capability_ttl if {
	d := authz.decision with input as request("fake_jira", "comment", "low_risk_write", "jira")
	some obligation in d.obligations
	obligation.kind == "capability_ttl_seconds"
	obligation.value <= 120
}

# --------------------------------------------------------------------------- deny

test_secret_access_is_always_denied if {
	d := authz.decision with input as request("fake_cloud", "get_secret", "secret_access", "cloud")
	d.outcome == "DENY"
	d.reason_code == "secret_access_always_denied"
}

# Secret access is denied on the risk class alone, even for a tool and operation that
# would otherwise be a permitted read. Classification cannot be laundered by choosing a
# benign-looking operation name.
test_secret_risk_class_denies_even_a_readable_operation if {
	d := authz.decision with input as request("fixture_repo", "read_file", "secret_access", "fixture")
	d.outcome == "DENY"
	d.reason_code == "secret_access_always_denied"
}

test_forbidden_operation_is_denied if {
	d := authz.decision with input as request("github", "delete_branch", "irreversible", "github")
	d.outcome == "DENY"
	d.reason_code == "operation_forbidden"
}

# A forbidden operation stays forbidden even when mislabelled as read-only. The deny list
# is checked before the risk class is trusted.
test_forbidden_operation_denied_despite_read_only_label if {
	d := authz.decision with input as read_request("fixture_repo", "write_file")
	d.outcome == "DENY"
	d.reason_code == "operation_forbidden"
}

test_unknown_tool_is_denied if {
	d := authz.decision with input as read_request("totally_new_tool", "read_file")
	d.outcome == "DENY"
	d.reason_code == "unknown_tool"
}

test_unknown_operation_on_a_known_tool_is_denied if {
	d := authz.decision with input as read_request("fixture_repo", "exfiltrate")
	d.outcome == "DENY"
	d.reason_code == "default_deny"
}

test_unknown_resource_scheme_is_denied if {
	d := authz.decision with input as request("fixture_repo", "read_file", "read_only", "file")
	d.outcome == "DENY"
	d.reason_code == "unknown_resource_scheme"
}

# The enumeration and the risk class must agree. A read operation labelled as a write is
# denied rather than allowed on the strength of being on the read list.
test_read_operation_labelled_mutating_is_denied if {
	d := authz.decision with input as request(
		"fixture_repo", "read_file", "high_risk_write", "fixture",
	)
	d.outcome == "DENY"
	d.reason_code == "default_deny"
}

test_empty_input_is_denied if {
	d := authz.decision with input as {}
	d.outcome == "DENY"
}

test_missing_action_is_denied if {
	d := authz.decision with input as {"principal": {"id": "x"}}
	d.outcome == "DENY"
}

# --------------------------------------------------------------------------- structure

# The decision document is always defined. An undefined decision would make OPA omit
# `result`, and while the client treats that as a denial (AS-008), the policy should never
# rely on the client's error handling for its default.
test_decision_is_always_defined if {
	authz.decision.outcome with input as {}
	authz.decision.outcome with input as {"action": {}}
	authz.decision.outcome with input as read_request("anything", "at_all")
}

test_every_outcome_is_one_of_three if {
	outcomes := {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
	authz.decision.outcome in outcomes with input as read_request("fixture_repo", "read_file")
	authz.decision.outcome in outcomes with input as request("fake_jira", "create_issue", "high_risk_write", "jira")
	authz.decision.outcome in outcomes with input as {}
}

# Guards against a wildcard creeping in: no tool may permit an operation that is also on
# the forbidden list for that tool.
test_no_operation_is_both_permitted_and_forbidden if {
	every tool, operations in authz.forbidden_operations {
		count(operations & object.get(authz.read_operations, tool, set())) == 0
		count(operations & object.get(authz.approval_operations, tool, set())) == 0
	}
}
