# Slice Stop/Go Checklist

A slice is not complete until every box is ticked. Do not begin the next slice while any required
check fails.

## S0 -> S1

- [ ] lint, typecheck, pytest green
- [ ] CI green **with no credentials configured**
- [ ] `docker compose config` valid
- [ ] `uv run task validate-package` passes
- [ ] migrations upgrade and downgrade cleanly
- [ ] config and log redaction verified against known secret patterns
- [ ] `scripts/preflight.ps1` confirms Docker daemon, pinned images, uv env, WSL resource caps
- [ ] `docs/THREAT_MODEL.md` committed, with a non-empty out-of-scope section
- [ ] `docs/adr/` exists with a template

## S1 -> S2

- [ ] unknown action denied
- [ ] OPA outage denied (stop the container mid-suite; every decision becomes DENY)
- [ ] digest mutation denied
- [ ] expired approval and expired capability denied
- [ ] wrong tool / wrong resource / wrong digest capability denied
- [ ] invalid signature denied
- [ ] replayed `jti` denied
- [ ] `opa test policy/` and `opa check --strict policy/` pass
- [ ] **all authorization tests run and pass with `ANTHROPIC_API_KEY` unset**
- [ ] import-graph test proves no module under `agent/` reaches the capability minter
- [ ] canonicalization golden fixtures cover NFC, float rejection, null-vs-absent, list order,
      domain-separation prefix

## S2 -> S3

- [ ] gateway is the sole tool-dispatch path
- [ ] invalid capability produces **zero** backend calls
- [ ] repository fixture blocks traversal and symlink escape
- [ ] fake-cloud and Jira writes are idempotent through the execution ledger
- [ ] worker restart mid-workflow demonstrated; workflow resumes
- [ ] approval wait survives worker restart
- [ ] approval expiry resolves to a terminal denied-expired state, not an indefinite wait
- [ ] side-effect retry produces one logical mutation
- [ ] policy denial is non-retryable
- [ ] workflow replay tests pass against recorded histories
- [ ] no generic model-controlled shell; typed scanner arguments only
- [ ] sandbox: non-root, no Docker socket, network default-deny, workspace escape blocked,
      timeout terminates, per-run volume reaped
- [ ] `agentsec approve | deny | list` CLI works end to end

## S3 -> S4

- [ ] 100+ scenarios
- [ ] deterministic hard metrics (no LLM judge for any hard metric)
- [ ] baseline frozen by ADR **before** any tuning
- [ ] thresholds committed and hashed **before** the ablation runner executes beyond smoke
- [ ] AS-038 refuses a non-smoke run when baseline/threshold hashes are unlocked
- [ ] all ten cells complete (2 planners x 5 control stacks)
- [ ] both axes reported separately
- [ ] failures retained; no case dropped
- [ ] README metrics generated from committed artifacts
- [ ] reports state sample sizes, repeats and confidence intervals
- [ ] no claim of a "proven zero rate"; no claim of exactly-once on an API without idempotency keys

## Final gate

- [ ] OTel traces, Prometheus metrics and Grafana dashboard work
- [ ] approval UI shows exact action, resource, arguments, evidence and digest — not only model
      rationale
- [ ] approval UI escapes all untrusted content; CSRF/origin protection present
- [ ] injection demo distinguishes **attempted** from **executed**
- [ ] durable recovery demo documented
- [ ] clean setup reproducible from the README on a fresh machine
