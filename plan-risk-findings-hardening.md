# Risk Findings and Analysis Hardening

## Sprint Goal

Make `execell analyze` explain why it reached its verdict. Risk output must
contain stable finding names, weights, and human-readable explanations instead
of exposing only an opaque score.

## Delivered Scope

- [x] Reuse `execell::risk::Engine` for analyze decisions.
- [x] Emit findings for policy violations, network activity, child processes,
  failed syscalls, and target failure.
- [x] Preserve `allow`, `review`, and `reject` CLI verdicts.
- [x] Add `risk_level` beside `risk_score`.
- [x] Store findings in session `summary.json`.
- [x] Include findings in terminal and JSON output.

## Finding Rules

| Finding | Weight | Behavior |
|---|---:|---|
| `policy_violation` | 0 | Immediate reject |
| `network_activity` | 20 | Review threshold contributor |
| `child_process` | 5 | Low-risk contributor |
| `failed_syscall` | 10 | Low-risk contributor |
| `target_failure` | 0 | Immediate reject |

Risk engine thresholds remain: low below 25, medium at 25, high at 50,
critical at 75. `medium` maps to CLI verdict `review`; high/critical map to
`reject`.

## Verification

```sh
cmake --build build-manual -j2
ctest --test-dir build-manual --output-on-failure
./build-manual/execell analyze --format json \
  --deny-path /etc/shadow \
  ./build-manual/execell_manual_fixture risk
```

The JSON result must contain `verdict`, `risk_level`, `risk_score`, and a
non-empty `findings` array. Session `summary.json` must contain the same risk
decision and findings.

## Remaining Work

- [x] Add stable finding IDs and resource/context fields.
- [x] Separate observed behavior from policy decision.
- [x] Add timeout and output-limit findings.
- [x] Move orchestration from `main.cpp` into an analysis library.
- [x] Attach concrete event context to policy findings.
- [ ] Attach source event context to aggregate observed findings.
