#!/usr/bin/env python3
"""Replay real access logs to DefMon from a second terminal.

This script is designed for Windows usage but works cross-platform.
It replays existing Apache/Nginx combined-format access logs and can inject
malicious payloads inside original request URIs to validate detection + SOAR.

Endpoint used:
    POST /api/senders/ingest?sender_id=<id>&sender_key=<key>
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
from pathlib import Path
from typing import Iterable
from urllib import parse, request

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"$'
)

PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "..%2f..%2fetc/passwd",
    "1 UNION SELECT username,password FROM users--",
]


def post_batch(
    api_base: str, sender_id: str, sender_key: str, lines: list[str], timeout: int
) -> dict:
    query = parse.urlencode({"sender_id": sender_id, "sender_key": sender_key})
    url = f"{api_base.rstrip('/')}/api/senders/ingest?{query}"

    payload = json.dumps({"lines": lines}).encode("utf-8")
    req = request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def inject_payload(line: str, payload: str) -> str:
    """Inject payload into the URI while preserving original log structure."""
    match = COMBINED_RE.match(line)
    if not match:
        return line

    uri = match.group("uri")
    encoded_payload = parse.quote_plus(payload)

    if "?" in uri:
        new_uri = f"{uri}&q={encoded_payload}"
    else:
        new_uri = f"{uri}?q={encoded_payload}"

    return (
        f"{match.group('ip')} - - [{match.group('ts')}] "
        f'"{match.group("method")} {new_uri} {match.group("proto")}" '
        f"{match.group('status')} {match.group('bytes')} "
        f'"{match.group("ref")}" "{match.group("ua")}"'
    )


def replay_lines(
    lines: Iterable[str],
    inject_every: int,
    random_seed: int,
) -> list[str]:
    randomizer = random.Random(random_seed)
    output: list[str] = []

    for index, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue

        if COMBINED_RE.match(line) and inject_every > 0 and index % inject_every == 0:
            payload = randomizer.choice(PAYLOADS)
            output.append(inject_payload(line, payload))
        else:
            output.append(line)

    return output


def chunks(lines: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(lines), size):
        yield lines[i : i + size]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replay real access logs to DefMon and "
            "inject malicious payloads into original lines."
        )
    )
    parser.add_argument(
        "--api-base", required=True, help="DefMon API URL, e.g. http://127.0.0.1:8000"
    )
    parser.add_argument("--sender-id", required=True, help="Sender ID from DefMon admin")
    parser.add_argument("--sender-key", required=True, help="Sender API key from DefMon admin")
    parser.add_argument(
        "--source-log",
        required=True,
        help="Path to a real combined-format access log file",
    )
    parser.add_argument("--batch-size", type=int, default=50, help="Lines per ingest request")
    parser.add_argument("--interval-seconds", type=float, default=1.0, help="Delay between batches")
    parser.add_argument("--timeout-seconds", type=int, default=15, help="HTTP request timeout")
    parser.add_argument(
        "--inject-every",
        type=int,
        default=8,
        help="Inject one malicious payload into every Nth original line (0 disables)",
    )
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for payload selection")
    args = parser.parse_args()

    source_path = Path(args.source_log)
    if not source_path.exists() or not source_path.is_file():
        raise SystemExit(f"source log not found: {source_path}")

    with source_path.open("r", encoding="utf-8", errors="replace") as f:
        source_lines = f.readlines()

    replay = replay_lines(source_lines, inject_every=args.inject_every, random_seed=args.seed)
    if not replay:
        raise SystemExit("source log has no usable lines")

    print(f"Loaded {len(replay)} lines from {source_path}")
    print(f"Sending to {args.api_base}/api/senders/ingest in batches of {args.batch_size}")

    sent = 0
    for batch in chunks(replay, args.batch_size):
        result = post_batch(
            api_base=args.api_base,
            sender_id=args.sender_id,
            sender_key=args.sender_key,
            lines=batch,
            timeout=args.timeout_seconds,
        )
        sent += len(batch)
        print(
            "sent={} accepted={} rejected={} malicious={} normal={} alerts={}".format(
                len(batch),
                result.get("accepted_lines", 0),
                result.get("rejected_lines", 0),
                result.get("malicious_lines", 0),
                result.get("normal_lines", 0),
                result.get("generated_alerts", 0),
            )
        )
        time.sleep(args.interval_seconds)

    print(f"Replay complete. Total lines sent: {sent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
