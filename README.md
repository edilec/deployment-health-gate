# deployment-health-gate

Offline, read-only rollout health decision from a versioned policy and captured metric samples. It never deploys.

## Run

Node.js 22+; no dependencies or network calls.

```sh
node bin/deployment-health-gate.mjs --root examples/pass --policy policy.json --capture capture.json
node bin/deployment-health-gate.mjs --root examples/fail --policy policy.json --capture capture.json
npm run check
```

One JSON report goes to stdout. Exit 0=`pass`/`allow`, 1=`fail`/`block`, 2=`incomplete`/`unknown` or invalid configuration. Invalid options, root, or policy leave stdout empty. Unreadable or invalid capture emits an incomplete report. Both input paths are realpath-confined within `--root`, strict UTF-8 and duplicate decoded JSON keys are enforced, and no files are written.

## Input and decision

Policy: `{"schemaVersion":"1","policyVersion":"v1","observationWindowMs":60000,"minSamples":2,"noData":"incomplete","requiredMetrics":[{"name":"error_rate","max":0.02}]}`. `noData` may be `incomplete` or `fail`, never pass. An optional `metadata` object is explicitly non-semantic. Each required metric has a maximum acceptable non-negative finite value. Values above it block. The observation window includes both its start and cutoff; samples before it are ignored. Every in-window sample must contain every required metric. Fewer than `minSamples` for any metric, missing values, duplicate sample IDs, partial capture, future samples, or malformed timestamps produce `incomplete`/`unknown` (except a deliberate no-data `fail` policy).

Capture: `{"schemaVersion":"1","complete":true,"observedAt":"2026-09-25T10:00:00Z","samples":[{"id":"s1","at":"2026-09-25T09:59:00Z","metrics":{"error_rate":0.01}}]}`. Required metrics must be own exported fields, not inherited properties. Times require ISO 8601 with an explicit `Z` or numeric offset, and compare as instants. `observedAt` is the capture cutoff, not a live clock read. The report uses fixed messages and logical pointers, not metric names or values. An optional capture `metadata` object is non-semantic. No traffic shaping, deployment, rollback, or live monitoring is performed.

## Limits

Policy ≤65,536 bytes; capture ≤1,048,576 bytes; at most 100 required metrics, 10,000 samples, JSON depth 16, and 5,000 ms evaluation with an injected monotonic clock. Policy window is 1,000–86,400,000 ms, and `minSamples` 1–10,000. Boundary N passes validation; N+1 is invalid or incomplete as appropriate.
