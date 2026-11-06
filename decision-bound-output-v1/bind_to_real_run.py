"""Binds decision-bound-output-v1 to a REAL probity_observer/REMORA run --
same source, same pins, same mapping conventions already fixed in
../build_vectors.py (action_ref_preimage / decision_preimage), applied to
AR-00 (the control case: full decision -> attempt -> terminal write chain,
the only case with a real completed write) and, since 2026-11-06, AR-04
(a second real case from the SAME pinned run, used only as the source of
a second, genuinely distinct real decision -- see "THE THIRD CASE" below).

Source of the per-case record: a REAL run of
probityai/agent-evidence-observer, examples/remora_effect_bridge.py,
commit 04b495d823dbcc49fa47b28fe1ba359dba8d4553 (same pin as
../PROVENANCE.md), against REMORA vectors pinned at
darklordVirtual/REMORA-research commit b25e735d36590154ff53768b4d245ad4c7996f64
(sha256 f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27 --
verified to match PROVENANCE.md's own pin before this run).

Run executed 2026-10-14 by the creator's explicit `!` (external,
untrusted-by-default code -- same rule as the original run that produced
../PROVENANCE.md). `--verify` passed first
({"status": "retained-cases-checked", ...}) before this script read a
single retained file.

This script does NOT modify or fork Observer -- it is a read-only overlay,
same pattern as ../build_vectors.py: it reads the real retained JSON
(approved-request.json / grant.json / attempt.json / approved-content.bin)
and computes what a dispatcher COULD HAVE bound its output_hash to under
decision-bound-output-v1, using the real decision/content values. The
actual Observer run still only produced the legacy (unbound) output_hash --
this demonstrates the mechanism retrofitted onto real data, not a claim
that Observer itself implements it.

OUTPUT SHAPE (fixed 2026-10-14, bug found by ogasurfproject-jpg's blind
read of 301b1dc): this writes cases in the SAME shape
verify_decision_bound.py's verify_case() expects everywhere else
(case_id / content_sha256 / decision_preimage / claimed_decision_id /
recorded_output_hash / expected_code).

THE THIRD CASE (added 2026-11-06, astrogilda's ask on
probityai/agent-evidence-vectors#349: "post the file-domain run on #349
... It needs three writes: one embedding the covering decision_ref, one
embedding another decision's ref, and one with no ref, which stays
indeterminate."). AR-00-REAL-AS-OBSERVED and AR-00-REAL-DECISION-BOUND
already covered the first and third write (added 2026-10-14, see above).
The second write -- "embeds another decision's ref" -- needed a second,
genuinely real, genuinely distinct decision to embed, not a placeholder
hash. AR-04 is that source: a second real case from the exact same pinned
run (same run_dir, same source-pins.json), with the SAME real content
(run-report.json confirms AR-04's `nativeWriteEvents: 0` -- its dispatch
was refused at the configuration-check stage, `localOutcome:
CONTEXT_CHANGED`, so it never produced a completed write of its own) but
a real, independently-computed decision_id: its grant and attempt are
real retained artifacts from the real run, and running them through the
exact same action_ref_preimage/decision_preimage mapping this file
already uses for AR-00 gives a real decision_id that differs from AR-00's
only because the two cases' real `executionDigest` values differ (folded
into `policy_id`) -- not a fabricated or arbitrary value.
AR-00-REAL-SUBSTITUTED is AR-00's real content and real cited decision
(the citation recomputes correctly, same as AR-00-REAL-DECISION-BOUND),
but with `recorded_output_hash` actually bound against AR-04's real
decision_id instead of the one cited -- the real-run analogue of the
synthetic DECISION-BOUND-SUBSTITUTED vector in ../vectors_decision_bound.json.
Expected code: BINDING_MISMATCH. AR-04's own decision_preimage is not
part of the vector verify_case() reads (the verifier does not need it to
reach BINDING_MISMATCH), but is recorded in this case's `source` block so
a reader can independently confirm recorded_output_hash really does
equal bound_output_hash(content_sha256, AR-04's real decision_id), not an
arbitrary value asserted without a traceable source.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from decision_bound import bound_output_hash, decision_id_from_preimage, legacy_output_hash

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jcs import jcs_bytes  # noqa: E402

VERSION = "execution-join-ref-v1"
CANON_PROFILE_ID = "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(preimage: dict) -> str:
    return "sha256:" + sha256_hex(jcs_bytes(preimage))


def iso_to_ms(iso: str) -> int:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def action_ref_preimage(request: dict, ts_ms: int) -> dict:
    # Same mapping as ../build_vectors.py's action_ref_preimage -- our own
    # choice, not Observer's or the spec's, documented there.
    return {
        "actor_id": request["principal_id"],
        "input_hash": "sha256:" + request["content_sha256"],
        "scope": f"{request['tool_id']}:{request['target_path']}",
        "ts_ms": ts_ms,
        "version": VERSION,
    }


def load_real_decision(run_dir: Path, case_id: str) -> dict:
    """Reads one case's real retained artifacts and computes its real
    decision_preimage/decision_id under this file's mapping convention.
    Used for AR-00 (the control case, has a real completed write) and
    AR-04 (used only as a source of a second real decision -- see module
    docstring, THE THIRD CASE)."""
    case_dir = run_dir / case_id

    request = json.loads((case_dir / "approved-request.json").read_text())
    grant = json.loads((case_dir / "grant.json").read_text())
    attempt = json.loads((case_dir / "attempt.json").read_text())
    content_bytes = (case_dir / "approved-content.bin").read_bytes()

    real_content_sha256 = sha256_hex(content_bytes)
    if real_content_sha256 != request["content_sha256"]:
        raise SystemExit(
            f"{case_id}: approved-content.bin does not hash to the retained request's "
            "content_sha256 -- refusing to proceed"
        )

    decision_ts_ms = iso_to_ms(grant["issuedAt"])
    policy_id = f"{grant['profile']}/{attempt['executionDigest']}"

    approved_preimage = action_ref_preimage(request, decision_ts_ms)
    approved_action_ref = ref(approved_preimage)

    decision_preimage = {
        "action_ref": approved_action_ref,
        "canonicalization_profile_id": CANON_PROFILE_ID,
        "outcome": "permit",
        "policy_id": policy_id,
        "ts_ms": decision_ts_ms,
    }
    decision_id = decision_id_from_preimage(decision_preimage)

    return {
        "case_id": case_id,
        "request": request,
        "grant": grant,
        "attempt": attempt,
        "content_sha256": real_content_sha256,
        "decision_preimage": decision_preimage,
        "decision_id": decision_id,
    }


def source_block(d: dict) -> dict:
    return {
        "observer_commit": "04b495d823dbcc49fa47b28fe1ba359dba8d4553",
        "remora_commit": "b25e735d36590154ff53768b4d245ad4c7996f64",
        "remora_vectors_sha256": "f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27",
        "approved_request": d["request"],
        "grant_issued_at_iso": d["grant"]["issuedAt"],
        "grant_profile": d["grant"]["profile"],
        "execution_digest": d["attempt"]["executionDigest"],
    }


def main() -> None:
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/remora-run-decisionbound")

    ar00 = load_real_decision(run_dir, "AR-00")
    ar04 = load_real_decision(run_dir, "AR-04")

    legacy_hash = legacy_output_hash(ar00["content_sha256"])
    bound_hash = bound_output_hash(ar00["content_sha256"], ar00["decision_id"])
    substituted_hash = bound_output_hash(ar00["content_sha256"], ar04["decision_id"])

    as_observed = {
        "case_id": "AR-00-REAL-AS-OBSERVED",
        "synthetic": False,
        "source": source_block(ar00),
        "content_sha256": ar00["content_sha256"],
        "decision_preimage": ar00["decision_preimage"],
        "claimed_decision_id": ar00["decision_id"],
        "recorded_output_hash": legacy_hash,
        "expected_code": "ORDERING_UNVERIFIABLE",
        "note": (
            "What Observer's real run actually produced today: output_hash is the "
            "legacy content-only commitment, decision_id is never folded in. Not a "
            "tampering finding -- this write simply predates the mechanism. This is "
            "the 'no ref embedded' write of astrogilda's three (probityai/"
            "agent-evidence-vectors#349)."
        ),
    }
    decision_bound = {
        "case_id": "AR-00-REAL-DECISION-BOUND",
        "synthetic": False,
        "source": source_block(ar00),
        "content_sha256": ar00["content_sha256"],
        "decision_preimage": ar00["decision_preimage"],
        "claimed_decision_id": ar00["decision_id"],
        "recorded_output_hash": bound_hash,
        "expected_code": "COMMITMENT_AFTER_DECISION",
        "note": (
            "The same real content and the same real covering decision, retrofitted "
            "under decision-bound-output-v1 -- what the same write would have produced "
            "had the dispatcher folded decision_id into output_hash. This is the "
            "'embeds the covering decision_ref' write of astrogilda's three."
        ),
    }
    substituted = {
        "case_id": "AR-00-REAL-SUBSTITUTED",
        "synthetic": False,
        "source": {
            **source_block(ar00),
            "actually_bound_decision": {
                "case_id": "AR-04",
                "decision_preimage": ar04["decision_preimage"],
                "decision_id": ar04["decision_id"],
                "note": (
                    "A second real case from the same pinned run (same run_dir, same "
                    "source-pins.json). AR-04's own dispatch was refused at the "
                    "configuration-check stage (run-report.json: nativeWriteEvents=0, "
                    "localOutcome=CONTEXT_CHANGED) -- it never produced a completed write "
                    "of its own. Its grant and attempt are nonetheless real retained "
                    "artifacts, giving a real, independently-computed decision_id "
                    "(differing from AR-00's because the two cases' real executionDigest "
                    "values differ) to embed instead of the cited one -- not a "
                    "fabricated or arbitrary hash."
                ),
            },
        },
        "content_sha256": ar00["content_sha256"],
        "decision_preimage": ar00["decision_preimage"],
        "claimed_decision_id": ar00["decision_id"],
        "recorded_output_hash": substituted_hash,
        "expected_code": "BINDING_MISMATCH",
        "note": (
            "AR-00's real content, citing AR-00's real covering decision (the citation "
            "recomputes correctly) -- but recorded_output_hash was actually bound "
            "against AR-04's real decision_id instead. Real-run analogue of "
            "../vectors_decision_bound.json's synthetic DECISION-BOUND-SUBSTITUTED. "
            "This is the 'embeds another decision's ref' write of astrogilda's three."
        ),
    }

    out_path = Path("vectors_decision_bound_real_run.json")
    out_path.write_text(json.dumps(
        {"profile": "decision-bound-output-v1-real-run", "cases": [as_observed, decision_bound, substituted]},
        indent=2, sort_keys=True,
    ))
    print(f"wrote {out_path}")
    print(f"AR-00 content_sha256        = {ar00['content_sha256']}")
    print(f"AR-00 decision_id (cited)   = {ar00['decision_id']}")
    print(f"AR-04 decision_id (bound)   = {ar04['decision_id']}")
    print(f"legacy_output_hash          = {legacy_hash}")
    print(f"decision_bound_output_hash  = {bound_hash}")
    print(f"substituted_output_hash     = {substituted_hash}")


if __name__ == "__main__":
    main()
