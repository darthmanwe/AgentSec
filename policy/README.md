# Policy bundle

Default-deny Rego, written in **v1 syntax** (OPA 1.x makes `if` and `contains`
mandatory on all rules). Filled in by AS-009.

Mounted read-only into the OPA container: the policy bundle is trusted input, and
OPA must not be able to rewrite the rules it is enforcing.

Run the tests through the pinned container, since `opa` is not installed on the host:

    uv run task opa-test
    uv run task opa-check
