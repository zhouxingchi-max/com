#!/usr/bin/env python3
"""安全、低速地检查 5 字母 .com 域名是否可能可注册。

说明：
- 默认低频请求，降低被误判为攻击/滥用的风险。
- 通过 RDAP 查询，返回结果仅供参考，最终可注册状态以注册商实时结果为准。
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import random
import string
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

ALPHABET = string.ascii_lowercase
RDAP_COM = "https://rdap.verisign.com/com/v1/domain/{domain}"


@dataclass
class Config:
    min_delay: float
    max_delay: float
    timeout: float
    max_retries: int
    retry_base_sleep: float
    user_agent: str


def iter_five_letter_labels(start_after: Optional[str] = None) -> Iterator[str]:
    started = start_after is None
    for tup in itertools.product(ALPHABET, repeat=5):
        label = "".join(tup)
        if not started:
            if label == start_after:
                started = True
            continue
        yield label


def check_domain_rdap(domain: str, cfg: Config) -> tuple[str, int, str]:
    """返回 (status, http_code, note)。

    status:
      - available: RDAP 返回 404（通常表示未注册）
      - registered: RDAP 返回 200
      - uncertain: 网络或服务端异常，无法确认
    """
    url = RDAP_COM.format(domain=domain)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json;q=0.9",
            "User-Agent": cfg.user_agent,
        },
    )

    for attempt in range(cfg.max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
                code = resp.getcode() or 0
                if code == 200:
                    return ("registered", code, "RDAP found record")
                return ("uncertain", code, f"Unexpected HTTP {code}")
        except urllib.error.HTTPError as e:
            code = e.code
            if code == 404:
                return ("available", code, "RDAP 404 (likely unregistered)")
            if code in (429, 500, 502, 503, 504) and attempt < cfg.max_retries:
                sleep_s = cfg.retry_base_sleep * (2**attempt) + random.uniform(0.0, 0.5)
                time.sleep(sleep_s)
                continue
            return ("uncertain", code, f"HTTPError {code}")
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < cfg.max_retries:
                sleep_s = cfg.retry_base_sleep * (2**attempt) + random.uniform(0.0, 0.5)
                time.sleep(sleep_s)
                continue
            return ("uncertain", -1, f"NetworkError: {e}")

    return ("uncertain", -1, "Exhausted retries")


def save_state(state_path: Path, last_label: str) -> None:
    state_path.write_text(json.dumps({"last_label": last_label}, ensure_ascii=False, indent=2), encoding="utf-8")


def load_state(state_path: Path) -> Optional[str]:
    if not state_path.exists():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        value = data.get("last_label")
        if isinstance(value, str) and len(value) == 5 and value.isalpha() and value.islower():
            return value
    except json.JSONDecodeError:
        return None
    return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="低速检查 5 字母 .com 域名 RDAP 状态")
    p.add_argument("--max-queries", type=int, default=100, help="本次最多查询数量（默认 100）")
    p.add_argument("--min-delay", type=float, default=1.2, help="每次查询最小延迟秒数")
    p.add_argument("--max-delay", type=float, default=2.5, help="每次查询最大延迟秒数")
    p.add_argument("--timeout", type=float, default=8.0, help="单次请求超时秒数")
    p.add_argument("--max-retries", type=int, default=3, help="可重试错误最大重试次数")
    p.add_argument("--retry-base-sleep", type=float, default=1.0, help="指数退避基准秒数")
    p.add_argument("--start-after", type=str, default=None, help="从某个 5 字母标签之后开始")
    p.add_argument("--resume", action="store_true", help="从 state.json 自动续跑")
    p.add_argument("--state-file", type=Path, default=Path("state.json"), help="进度文件路径")
    p.add_argument("--output", type=Path, default=Path("results.csv"), help="输出 CSV 路径")
    p.add_argument(
        "--user-agent",
        type=str,
        default="safe-domain-checker/1.0 (contact: you@example.com)",
        help="请求 UA（建议填可联系邮箱）",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.min_delay <= 0 or args.max_delay < args.min_delay:
        raise SystemExit("Invalid delay settings: require 0 < min_delay <= max_delay")
    if args.max_queries <= 0:
        raise SystemExit("--max-queries must be > 0")

    cfg = Config(
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        timeout=args.timeout,
        max_retries=args.max_retries,
        retry_base_sleep=args.retry_base_sleep,
        user_agent=args.user_agent,
    )

    start_after = args.start_after
    if args.resume:
        resumed = load_state(args.state_file)
        if resumed:
            start_after = resumed
            print(f"[resume] from: {start_after}")

    write_header = not args.output.exists()
    count = 0
    with args.output.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["label", "domain", "status", "http_code", "note", "checked_at_unix"])

        for label in iter_five_letter_labels(start_after=start_after):
            if count >= args.max_queries:
                break

            domain = f"{label}.com"
            status, code, note = check_domain_rdap(domain, cfg)
            ts = int(time.time())
            writer.writerow([label, domain, status, code, note, ts])
            f.flush()

            save_state(args.state_file, label)
            count += 1
            print(f"[{count}/{args.max_queries}] {domain}: {status} ({code})")

            time.sleep(random.uniform(cfg.min_delay, cfg.max_delay))

    print(f"Done. wrote {count} rows -> {args.output}")
    print("注意：'available' 仅为 RDAP 角度的高概率可注册，实际以注册商实时查询为准。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
