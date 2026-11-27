# Cases the outer loop found

Each file here holds kernel steps, in the differential's case format, that the outer loop (`scripts/outer-loop.sh`, the `outer-loop` workflow) found the Rust, Bend or wasm kernel disagreeing on. `scripts/check.sh` replays every `*.jsonl` here through Bend and wasm on every push, next to the random cases.

Add a case in the pull request that fixes the disagreement, so it fails before the fix and passes after it. Name the file for the fingerprint, for example `renew-in-run-deadline.jsonl`. Do not delete one to make a check pass.
