# Analyze Workflow Foundation

## Sprint Goal

Turn ExeCell's existing tracing and policy primitives into one repeatable
analysis workflow:

```text
target -> trace -> policy -> summary -> risk verdict -> session artifacts
```

The workflow must remain rootless and must not claim complete malware
protection. It reports observed behavior and fails closed when configured policy
rules are violated.

## Sprint Scope

- [x] Add `execell analyze` as the user-facing workflow command.
- [x] Reuse existing tracer, event model, policy engine, and reporters.
- [x] Support terminal and JSON output.
- [x] Create a session directory under `/tmp`.
- [x] Write `events.json` and `summary.json` artifacts.
- [x] Produce deterministic `allow`, `review`, or `reject` verdicts.
- [x] Support path, endpoint, syscall, and process-count policy options.
- [x] Exercise workflow with the manual risk fixture.

## CLI Contract

```sh
execell analyze [--format terminal|json] \
  [--deny-path PATH] [--deny-endpoint ENDPOINT] \
  [--deny-syscall NAME] [--max-processes N] \
  PROGRAM [ARGUMENTS...]
```

Terminal output includes summary counters, verdict, risk score, policy
violation count, and session path. JSON output includes the same top-level
result plus the event array.

## Risk Policy For Sprint

- Every policy violation adds 70 points.
- Every failed syscall adds 10 points.
- Every network attempt adds 20 points.
- Every spawned process adds 5 points.
- `reject`: policy violation or score >= 70.
- `review`: score 30-69.
- `allow`: score below 30 and target exits successfully.

This scoring is deliberately simple and deterministic. It is a workflow
placeholder, not a complete threat model.

## Verification

```sh
cmake -S . -B build-manual -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-manual -j2
ctest --test-dir build-manual --output-on-failure
./build-manual/execell analyze \
  --deny-path /etc/shadow \
  ./build-manual/execell_manual_fixture risk
./build-manual/execell analyze --format json \
  ./build-manual/execell_manual_fixture file
```

## Exit Contract

- `0`: verdict `allow` and target exit status `0`.
- non-zero: `review`, `reject`, invalid invocation, tracer failure, or target
  failure.

## Delivered Next-Sprint Work

- [x] Move analysis orchestration out of `main.cpp` into `src/analyze/analyze.cpp`.
- [x] Add dedicated stable risk finding IDs and context fields.
- [x] Add integration test that parses session JSON.
- [x] Add timeout and output limits to `analyze`.
- [x] Add sandbox selection to the workflow.

## Remaining Hardening

- [x] Feed sandbox outcome metadata into analysis reports.
- [x] Enforce combined stdout+stderr quota.
- [x] Add explicit timeout/output-limit event records to `events.json`.
- [x] Add sandbox attestation to session output.
- [ ] Feed sandbox ptrace events into the same policy event stream.
