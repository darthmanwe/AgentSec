# Running the funded evaluation

The Axis-A sweep is the only part of this project that spends money, and the intent is to
spend it **once**. This is the procedure, in order, with what each step protects against.

Read the whole thing before starting. The steps that matter are 1, 3 and 5.

---

## What protects the money

| Failure | What happens |
|---|---|
| Crash, power cut, Ctrl-C at 80% | The 80% is on disk. Every paid response is cached. `--resume` buys only the remainder. |
| Rate limit, overload, 5xx, dropped connection | Retried with exponential backoff and full jitter, six attempts, bounded. |
| One malformed request | That cell stops and is recorded as unscoreable. The run continues. |
| Authentication failure | The run stops immediately rather than burning retries confirming it. |
| Budget ceiling reached | The run stops with results captured and the artifact marked `budget_exhausted`. |
| A request that hangs forever | Hard 300s per-attempt timeout, independent of the SDK's own. |
| A run that will not finish | Wall-clock deadline, default 6 hours, stops with results captured. |
| A response that cannot be priced | Refused rather than settled at $0 — see the note at the end. |
| OPA down | **Preflight refuses to start.** OPA fails closed, so a run against a dead engine denies everything and reports a perfect score it did not earn. |

Nothing here protects against the API being unavailable for the whole window. If that
happens, the run stops, the cache keeps whatever was bought, and a resume picks up later.

---

## 1. Rehearse it, free

The dry run executes the **same cells, the same pipeline, the same scoring and the same
cache** on the deterministic mock. It is not a separate code path.

```bash
docker compose up -d opa
uv run python -m agentsec.eval.runner --suite full --axis real --axis adversarial \
    --dry-run --repeats 3
```

Expect `status: completed` and `complete: True`. If it does not complete, **do not run it
live** — whatever broke will break the same way with money attached.

This step has already earned its keep three times: it caught an arm referencing a prompt
nobody had written, a mock that bypassed the cache, and a dry-run artifact labelling
itself reportable.

## 2. Check the projection

```bash
uv run python -m agentsec.eval.runner --axis real --preflight-only --repeats 3
```

Prints the number of live calls and a **worst-case** cost — every call priced at its full
`max_tokens` of output, which almost never happens. Actual spend is typically a fraction.
Use it to decide the ceiling, not to predict the bill.

At three repeats across five arms and 22 injection cases the projection is roughly **660
calls, worst case ~$15** on Haiku 4.5.

## 3. Set the ceiling below what you are willing to lose

```bash
export AGENTSEC_ANTHROPIC_API_KEY=sk-ant-...
uv run python -m agentsec.eval.runner --suite full \
    --axis real --axis adversarial \
    --live --max-usd 18 \
    --repeats 3 --concurrency 2
```

`--live` must be typed. There is no path that infers it from a key being present, because
a key in the shell for unrelated reasons must never turn a free run into a paid one.

`--max-usd` is a hard ceiling enforced **before** each request: worst-case cost is reserved
first and reconciled against actual usage after. A call that will not fit is never sent.

Keep `--concurrency` at 2. Higher invites rate limiting, which retries absorb at the cost
of a slower run and no benefit.

## 4. Watch it

The run prints nothing until it finishes. Progress is in the run directory:

```bash
uv run python -m agentsec.eval.runner --list-runs
tail -f eval/runs/<run-id>/events.jsonl
```

Every case appends an event with the spend so far. Ctrl-C is safe: it cancels the run,
flushes the artifact, and marks it `interrupted`.

## 5. If it stops early

```bash
uv run python -m agentsec.eval.runner --suite full \
    --axis real --axis adversarial --live --max-usd 18 \
    --repeats 3 --resume <run-id>
```

The resume replays every cached response for free and buys only what is missing. It will
say so:

```
note: resumed: 7 of 10 cells already on disk, replaying cached responses
      rather than re-purchasing them
```

An incomplete run exits **3** and is marked `reportable: false` with the missing cells
named. A partial run is legitimate output; it is simply not a result.

## 6. Commit the evidence

`eval/artifacts/` is gitignored so exploratory runs do not accumulate. The artifact behind
a published number gets committed deliberately, along with the run's `run.json` and its
cell files. The cache does not need committing — it is large and reconstructible — but keep
it locally: it makes the run re-scorable without contacting the API again.

---

## Two things worth knowing

**The preregistration lock will block a run whose inputs drifted.** That is the mechanism
working. If you changed a prompt, the policy bundle, the registry or the corpus since
freezing, the run is a *different experiment* and needs its own preregistration —
deliberately, visibly, in a commit that says so. `freeze()` refuses to overwrite.

**A response with unreadable usage is refused, not settled at zero.** This was a real bug:
the decoder read token usage defensively like every other field, so a changed SDK response
shape would have produced zero tokens, settled every call at $0.00, and left the ledger
showing no spend at all — while the real money went out and the ceiling never fired. Usage
is now mandatory. If the SDK changes under you, the run fails loudly on the first call
instead of quietly spending the whole budget.
