import argparse
import datetime
import filecmp
import hashlib
import json
import os
import shutil
import struct
import uuid
from pathlib import Path

import replay_provider_proxy as proxy


def sha256_file(path, prefix=b""):
    digest = hashlib.sha256(prefix)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_path(root, name):
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("source path escapes its capture root")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError("source path escapes its capture root")
    return path


def success_response(row, size, output_hash):
    source = row["response"]
    result = source["operation_result"]
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ValueError("invalid native operation result")
    response = {
        "transport": source["transport"],
        "open_errno": source["open_errno"],
        "ioctl_errno": source["ioctl_errno"],
        "close_errno": source["close_errno"],
        "operation_result": int(result, 16),
        "output_size": source["output_size"],
        "cleanup": source["cleanup"],
        "dispatch": source["dispatch"],
        "success": True,
        "body_sha256": output_hash,
    }
    if row["output_size"] != size or not proxy.complete_success(response, size):
        raise ValueError("RNPS capture is not a complete native success")
    return response


def inspect_capture(run):
    inventory = json.loads((run / "bundle_inventory.json").read_text(encoding="utf-8"))
    firmware = Path(inventory["firmware_root"]).resolve(strict=True)
    known = {}
    for entry in inventory["entries"]:
        if entry["kind"] != "rnps":
            continue
        digest = entry["input_sha256"]
        if digest in known:
            raise ValueError("duplicate RNPS inventory input")
        known[digest] = entry
    rows = []
    journal = run / "bundle_records.jsonl"
    with journal.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("kind") == "rnps" and row.get("status") == "success":
                rows.append(row)
    found = []
    for row in rows:
        input_hash = row["input_sha256"]
        entry = known[input_hash]
        if (row["input_size"] != entry["input_size"]
                or row["source"] not in entry["paths"]
                or row["request_sha256"] != input_hash):
            raise ValueError("RNPS journal and inventory disagree")
        body_path = source_path(firmware, row["source"])
        output_path = source_path(run, row["output"])
        size = body_path.stat().st_size
        if size != entry["input_size"] or output_path.stat().st_size != size:
            raise ValueError("RNPS source or output size mismatch")
        with body_path.open("rb") as source:
            if source.read(8) != b"RNPSHEDR":
                raise ValueError("firmware input is not RNPS")
        fields = struct.pack("<IIIIIII", proxy.RNPS, 0, 0, 0, 0, size, size)
        identity = sha256_file(body_path, fields)
        if sha256_file(body_path) != input_hash:
            raise ValueError("firmware input hash changed")
        output_hash = sha256_file(output_path)
        if output_hash != row["output_sha256"]:
            raise ValueError("saved console output hash mismatch")
        request = {
            "opcode": proxy.RNPS,
            "cid": 0,
            "mkv": 0,
            "key_size": 0,
            "salt_size": 0,
            "input_size": size,
            "output_capacity": size,
            "identity": identity,
            "body_sha256": input_hash,
            "guest_input_sha256": input_hash,
        }
        response = success_response(row, size, output_hash)
        found.append({
            "identity": identity,
            "request": request,
            "response": response,
            "input_path": body_path,
            "output_path": output_path,
            "source_run": run,
            "source": row["source"],
            "source_output": row["output"],
        })
    return found


def same_capture(a, b):
    return (a["request"] == b["request"]
            and a["response"] == b["response"]
            and filecmp.cmp(a["input_path"], b["input_path"], shallow=False)
            and filecmp.cmp(a["output_path"], b["output_path"], shallow=False))


def same_base(store, item):
    identity = item["identity"]
    record_path = store.records / (identity + ".json")
    if not record_path.exists():
        return False
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if (record["request"] != item["request"]
            or record["response"] != item["response"]
            or not filecmp.cmp(store.requests / (identity + ".bin"), item["input_path"], shallow=False)
            or not filecmp.cmp(store.responses / (identity + ".bin"), item["output_path"], shallow=False)):
        raise ValueError("base replay response conflicts with sweep capture: " + identity)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-store", type=Path, required=True)
    parser.add_argument("--capture-run", type=Path, action="append", required=True)
    parser.add_argument("--new-store", type=Path, required=True)
    parser.add_argument("--expect-distinct-rnps", type=int, default=237)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source = proxy.Store(args.source_store.resolve(strict=True))
    source_counts = source.verify()
    if source_counts["conflicts"]:
        raise ValueError("source replay store has conflicts")
    runs = [path.resolve(strict=True) for path in args.capture_run]
    target = args.new_store.resolve()
    if target.exists():
        raise ValueError("new replay store must be absent")
    unique = {}
    success_rows = 0
    repeat_rows = 0
    for run in runs:
        for item in inspect_capture(run):
            success_rows += 1
            prior = unique.get(item["identity"])
            if prior is not None:
                if not same_capture(prior, item):
                    raise ValueError("conflicting captured console outputs: " + item["identity"])
                repeat_rows += 1
            else:
                unique[item["identity"]] = item
    if len(unique) != args.expect_distinct_rnps:
        raise ValueError("RNPS sweep coverage differs from expected distinct count")
    base_overlaps = sum(same_base(source, item) for item in unique.values())
    additions = len(unique) - base_overlaps
    expected = source_counts["records"] + additions
    report = {
        "schema": 1,
        "source_store": str(source.path),
        "capture_runs": [str(run) for run in runs],
        "source_records": source_counts["records"],
        "source_envelope_records": source_counts["envelope"],
        "source_rnps_records": source_counts["rnps"],
        "successful_capture_rows": success_rows,
        "duplicate_capture_rows_verified_identical": repeat_rows,
        "distinct_rnps_inputs_verified": len(unique),
        "existing_source_records_verified_identical": base_overlaps,
        "new_rnps_records": additions,
        "expected_total_records": expected,
        "provenance": "preupdate 13.60 bundle_capture authenticated live provider results, rechecked against archived firmware input and saved output SHA-256",
    }
    if args.dry_run:
        print(json.dumps(report, sort_keys=True))
        return
    stage = target.with_name(target.name + ".building-" + uuid.uuid4().hex)
    store = proxy.Store(stage)
    store.prepare("capture")
    for group in ("records", "requests", "responses"):
        for path in sorted((source.path / group).iterdir()):
            if not path.is_file():
                raise ValueError("unexpected source replay store entry")
            proxy.save_atomic(stage / group / path.name, path.read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in sorted(unique.values(), key=lambda value: value["identity"]):
        if (store.records / (item["identity"] + ".json")).exists():
            continue
        identity = item["identity"]
        record = {
            "schema": 1,
            "captured_at_utc": datetime.datetime.fromtimestamp(
                item["output_path"].stat().st_mtime, datetime.timezone.utc).isoformat(),
            "derived_at_utc": now,
            "provenance": "authenticated_live_console_provider",
            "source_evidence": {
                "capture_run": str(item["source_run"]),
                "journal": "bundle_records.jsonl",
                "firmware_source": item["source"],
                "input_sha256": item["request"]["body_sha256"],
                "output": item["source_output"],
                "output_sha256": item["response"]["body_sha256"],
            },
            "request": item["request"],
            "response": item["response"],
        }
        shutil.copyfile(item["input_path"], store.requests / (identity + ".bin"))
        shutil.copyfile(item["output_path"], store.responses / (identity + ".bin"))
        proxy.save_atomic(store.records / (identity + ".json"),
                          (json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
    counts = store.verify()
    if (counts["records"] != expected or counts["rnps"] != source_counts["rnps"] + additions
            or counts["envelope"] != source_counts["envelope"] or counts["conflicts"]):
        raise ValueError("derived replay store coverage mismatch")
    report["verified_store"] = counts
    proxy.save_atomic(stage / "backfill_audit.json",
                      (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    if target.exists():
        raise ValueError("new replay store appeared during build")
    os.rename(stage, target)
    print(json.dumps({"store": str(target), "verified": counts,
                      "audit_sha256": sha256_file(target / "backfill_audit.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
