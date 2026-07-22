#!/usr/bin/env python3
"""Continuously send realtime logs to DefMon with mixed normal and malicious entries.

This script:
1. Creates a sender if it doesn't exist
2. Sends batches of logs continuously
3. Randomly injects malicious payloads (SQL injection, XSS, path traversal)
4. Includes normal requests mixed with attacks
"""

import argparse
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# Realistic user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "Python-Requests/2.28.1",
]

# Normal URIs
NORMAL_URIS = [
    "/index.html",
    "/api/users",
    "/api/products",
    "/static/style.css",
    "/images/logo.png",
    "/health",
    "/docs",
    "/search?q=python",
    "/blog/article-1",
    "/contact",
]

# Malicious URIs
MALICIOUS_URIS = [
    "/search?q=1' OR 1=1--",
    "/login?user=admin'--&password=anything",
    "/api/users?id=1 UNION SELECT * FROM passwords--",
    "/download?file=../../../../etc/passwd",
    "/products?id=<script>alert('xss')</script>",
    "/api/data?filter='; DROP TABLE users;--",
    "/upload?filename=../../../shell.php",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/api/admin?id=1' OR '1'='1",
]

# Normal IPs
NORMAL_IPS = [
    "192.168.1.100",
    "192.168.1.101",
    "10.0.0.5",
    "10.0.0.15",
    "172.16.0.100",
]

# Malicious IPs (threat intel flagged)
MALICIOUS_IPS = [
    "185.220.101.1",
    "45.155.205.233",
    "194.165.16.77",
    "109.70.100.1",
    "185.56.83.100",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
HTTP_STATUSES = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503]


class RealtimeLogSender:
    def __init__(
        self, api_base: str, sender_id: Optional[str] = None, sender_key: Optional[str] = None
    ):
        self.api_base = api_base.rstrip("/")
        self.sender_id = sender_id
        self.sender_key = sender_key
        self.session = requests.Session()

    def create_sender(
        self, admin_token: str, sender_name: str = "realtime-logger"
    ) -> tuple[str, str]:
        """Create a new sender and return (sender_id, sender_key)"""
        import time

        headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

        # Try with unique name if default exists
        unique_name = f"{sender_name}-{int(time.time())}"

        data = {
            "name": unique_name,
            "description": "Continuous realtime log sender with mixed normal and malicious events",
        }

        try:
            resp = self.session.post(
                f"{self.api_base}/api/senders", json=data, headers=headers, timeout=10
            )
            resp.raise_for_status()
            result = resp.json()
            self.sender_id = result["sender"]["id"]
            self.sender_key = result["api_key"]
            logger.info(f"✅ Created sender: {self.sender_id} (name: {unique_name})")
            return self.sender_id, self.sender_key
        except Exception as e:
            logger.error(f"❌ Failed to create sender: {e}")
            raise

    def generate_log_line(self, is_malicious: bool = False) -> str:
        """Generate a single Apache combined format log line"""
        ip = random.choice(MALICIOUS_IPS if is_malicious else NORMAL_IPS)
        method = random.choice(HTTP_METHODS)
        uri = random.choice(MALICIOUS_URIS if is_malicious else NORMAL_URIS)
        protocol = "HTTP/1.1"
        status = random.choice(HTTP_STATUSES)
        bytes_sent = random.randint(100, 50000)
        referrer = random.choice(["http://google.com", "http://example.com", "-"])
        user_agent = random.choice(USER_AGENTS)

        # Realistic timestamp (last 30 minutes)
        now = datetime.now()
        ts = now - timedelta(seconds=random.randint(0, 1800))
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

        # Apache combined format
        log_line = (
            f'{ip} - - [{ts_str}] "{method} {uri} {protocol}" '
            f'{status} {bytes_sent} "{referrer}" "{user_agent}"'
        )
        return log_line

    def send_logs(self, batch_size: int = 10, malicious_ratio: float = 0.3) -> dict:
        """Send a batch of logs with mixed normal and malicious entries"""
        if not self.sender_id or not self.sender_key:
            logger.error("Sender not configured. Call create_sender() first.")
            return {}

        # Generate batch with mixed logs
        batch = []
        for _ in range(batch_size):
            is_malicious = random.random() < malicious_ratio
            batch.append(self.generate_log_line(is_malicious))

        params = {"sender_id": self.sender_id, "sender_key": self.sender_key}
        headers = {"Content-Type": "application/json"}
        data = {"lines": batch}

        retries = 3
        for attempt in range(retries):
            try:
                resp = self.session.post(
                    f"{self.api_base}/api/senders/ingest",
                    json=data,
                    params=params,
                    headers=headers,
                    timeout=10,
                )
                resp.raise_for_status()
                result = resp.json()

                malicious_count = sum(
                    1 for line in batch if any(uri in line for uri in MALICIOUS_URIS)
                )
                logger.info(
                    f"✅ Sent batch: {len(batch)} logs "
                    f"({malicious_count} malicious, {len(batch) - malicious_count} normal) | "
                    f"Ingested: {result.get('accepted_lines', 0)}, "
                    f"Alerts: {result.get('generated_alerts', 0)}"
                )
                return result
            except Exception as e:
                if attempt < retries - 1:
                    logger.warning(
                        f"⚠️  Send failed (attempt {attempt + 1}/{retries}): "
                        f"{type(e).__name__}. Retrying..."
                    )
                    time.sleep(2)
                else:
                    logger.error(f"❌ Failed to send logs after {retries} attempts: {e}")
                    return {}

        return {}


def get_admin_token(api_base: str) -> str:
    """Get admin JWT token for authentication"""
    try:
        resp = requests.post(
            f"{api_base}/api/auth/login",
            data={"username": "admin", "password": "admin"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
    except Exception as e:
        logger.error(f"❌ Failed to get admin token: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Continuously send realtime logs with mixed normal and malicious entries"
    )
    parser.add_argument(
        "--api-base",
        default="http://localhost:8000",
        help="DefMon API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--sender-id", help="Existing sender ID (if not provided, will create new sender)"
    )
    parser.add_argument(
        "--sender-key", help="Existing sender API key (required if --sender-id is provided)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=10, help="Number of logs per batch (default: 10)"
    )
    parser.add_argument(
        "--interval", type=int, default=5, help="Seconds between batches (default: 5)"
    )
    parser.add_argument(
        "--malicious-ratio",
        type=float,
        default=0.3,
        help="Ratio of malicious logs (0.0-1.0, default: 0.3)",
    )
    parser.add_argument(
        "--duration", type=int, default=0, help="Run for N seconds (default: 0 = indefinitely)"
    )

    args = parser.parse_args()

    logger.add(sys.stderr, level="INFO")
    logger.info("🚀 DefMon Realtime Log Sender")
    logger.info(f"📡 API Base: {args.api_base}")

    sender = RealtimeLogSender(args.api_base, args.sender_id, args.sender_key)

    # Create sender if not provided
    if not args.sender_id:
        logger.info("🔑 Getting admin token...")
        admin_token = get_admin_token(args.api_base)
        logger.info("✅ Admin authenticated")

        logger.info("📝 Creating sender...")
        sender.create_sender(admin_token)
    else:
        sender.sender_id = args.sender_id
        sender.sender_key = args.sender_key

    logger.info(
        f"⚙️  Config: batch_size={args.batch_size}, "
        f"interval={args.interval}s, malicious_ratio={args.malicious_ratio:.1%}"
    )
    logger.info("📤 Starting log transmission...\n")

    start_time = time.time()
    batch_count = 0

    try:
        while True:
            # Check if duration exceeded (only if duration > 0)
            if args.duration > 0 and (time.time() - start_time) > args.duration:
                logger.info(f"⏱️  Duration exceeded. Stopping after {batch_count} batches.")
                break

            sender.send_logs(batch_size=args.batch_size, malicious_ratio=args.malicious_ratio)
            batch_count += 1

            if args.interval > 0:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info(f"\n⏹️  Stopped. Sent {batch_count} batches.")
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
