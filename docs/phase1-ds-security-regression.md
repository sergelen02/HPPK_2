# Phase 1: HPPK DS security-regression tests

## Purpose

This suite tests HPPK DS correctness and negative cases before any relay, blockchain, or benchmark result is treated as paper evidence.

## Test set

| Test | Required outcome |
|---|---|
| Valid Agent-A signature under Agent-A public key | accept |
| One-byte message modification | reject |
| Signature for a different message | reject |
| One-byte mutation of F, H, U, V | reject |
| Agent-A signature under independently generated Agent-B public key | reject |
| Valid Agent-B signature under Agent-B public key | accept |
| Public-key-only constructed forgery | reject |

## Run command

The public-only forgery test is deliberately behind the `securityregression` build tag. It will currently expose any verifier that accepts a public construction. Do not discard or overwrite this failure; preserve it as a vulnerability finding.

```bash
HPPK_ROOT=/home/sergelen.8711/workspace/HPPK_2
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-hppk-ds-security-r01"
RESULT_ROOT=/home/sergelen.8711/exp-hppk/results/security/"$RUN_ID"

mkdir -p "$RESULT_ROOT/raw"

cd "$HPPK_ROOT"
set -o pipefail

go test -tags securityregression ./internal/ds \
  -run '^TestSecurityRegression' \
  -count=1 -v \
  2>&1 | tee "$RESULT_ROOT/raw/hppk-ds-security-regression.txt"

TEST_EXIT="${PIPESTATUS[0]}"
echo "go_test_exit_code=$TEST_EXIT" | tee "$RESULT_ROOT/test-status.txt"

sha256sum \
  "$RESULT_ROOT/raw/hppk-ds-security-regression.txt" \
  "$RESULT_ROOT/test-status.txt" \
  > "$RESULT_ROOT/SHA256SUMS"

exit "$TEST_EXIT"
```

## Interpretation

- If all tests pass, record the run as an implementation-level correctness result only.
- If `TestSecurityRegressionRejectsPublicOnlyForgery` fails, the verifier accepts a signature constructed without a secret key. Stop relay and performance claims, preserve the raw evidence, and correct the HPPK verification implementation before rerunning under a new experiment ID.
- The small field used by this logic-level suite is not a Level-V performance result. Run the separate Phase-A Level-V test with independently generated keys after this suite is clean.
