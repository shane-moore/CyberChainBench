"""Batch runner for the live scrape agent."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Any, Iterable, Sequence

from project_layout import LIVE_SCRAPE_WORKSPACE_DIR

from .agent import LiveScrapeAgent


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _safe_name(value: str, fallback: str) -> str:
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or fallback


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "round",
        "slug",
        "label",
        "chain",
        "status",
        "case_id",
        "target_address",
        "case_link",
        "first_attack_tx",
        "attack_tx_confidence",
        "attack_tx_count",
        "pages",
        "txs",
        "report_links",
        "search_queries",
        "web_errors",
        "search_errors",
        "report_path",
        "output_dir",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def _write_markdown(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Live Scrape Batch Summary",
        "",
        "| Round | Target | Chain | Status | Target Address | Attack Tx | Confidence | Pages | Report |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        report_link = str(row.get("report_path", "")).strip()
        report_cell = f"[report]({report_link})" if report_link else ""
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row.get("round", "")),
                    str(row.get("label", "") or row.get("slug", "")),
                    str(row.get("chain", "")),
                    str(row.get("status", "")),
                    str(row.get("target_address", "")),
                    str(row.get("first_attack_tx", "")),
                    str(row.get("attack_tx_confidence", "")),
                    str(row.get("pages", "")),
                    report_cell,
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class LiveScrapeBatchTarget:
    slug: str
    label: str
    chain: str = ""
    address: str = ""
    tx_hashes: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()
    search_domains: tuple[str, ...] = ()
    search_limit: int = 3
    block: int | None = None
    max_transactions: int | None = None

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "LiveScrapeBatchTarget":
        slug = _safe_name(
            str(payload.get("slug", "") or payload.get("label", "") or payload.get("name", "")),
            "target",
        )
        label = str(payload.get("label", "") or payload.get("name", "") or slug).strip()
        block_value = payload.get("block")
        try:
            normalized_block = None if block_value in (None, "") else int(block_value)
        except (TypeError, ValueError):
            normalized_block = None
        max_transactions_value = payload.get("max_transactions")
        try:
            normalized_max_transactions = (
                None if max_transactions_value in (None, "") else int(max_transactions_value)
            )
        except (TypeError, ValueError):
            normalized_max_transactions = None
        return cls(
            slug=slug,
            label=label,
            chain=str(payload.get("chain", "")).strip(),
            address=str(payload.get("address", "")).strip(),
            tx_hashes=tuple(_dedupe_keep_order(payload.get("tx_hashes", []) or [])),
            urls=tuple(_dedupe_keep_order(payload.get("urls", []) or [])),
            queries=tuple(_dedupe_keep_order(payload.get("queries", []) or [])),
            search_domains=tuple(_dedupe_keep_order(payload.get("search_domains", []) or [])),
            search_limit=max(int(payload.get("search_limit", 3) or 3), 1),
            block=normalized_block,
            max_transactions=normalized_max_transactions,
        )

    def to_manifest_payload(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "label": self.label,
            "chain": self.chain,
            "address": self.address,
            "tx_hashes": list(self.tx_hashes),
            "urls": list(self.urls),
            "queries": list(self.queries),
            "search_domains": list(self.search_domains),
            "search_limit": self.search_limit,
            "block": self.block,
            "max_transactions": self.max_transactions,
        }


def load_batch_targets(path: Path, *, only: Iterable[str] = ()) -> list[LiveScrapeBatchTarget]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"expected a list of targets in {path}")
    targets = [
        LiveScrapeBatchTarget.from_mapping(item) for item in payload if isinstance(item, dict)
    ]
    only_set = {_safe_name(value, "") for value in only if str(value).strip()}
    if only_set:
        targets = [target for target in targets if target.slug in only_set]
    if not targets:
        raise ValueError(f"no targets selected from {path}")
    return targets


class LiveScrapeBatchRunner:
    """Run many live scrape targets in repeated rounds."""

    def __init__(self, base_dir: Path, *, max_transactions: int = 3, url_timeout: int = 20):
        self.base_dir = base_dir.resolve()
        self.max_transactions = max(int(max_transactions), 1)
        self.url_timeout = max(int(url_timeout), 1)

    def default_output_dir(self, *, name: str = "live-scrape-overnight") -> Path:
        slug = _safe_name(name, "live-scrape-batch")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.base_dir / LIVE_SCRAPE_WORKSPACE_DIR / "batches" / f"{stamp}_{slug}"

    def _build_summary_row(
        self,
        *,
        round_index: int,
        target: LiveScrapeBatchTarget,
        report: dict[str, Any],
        report_path: Path,
        output_dir: Path,
    ) -> dict[str, Any]:
        evidence = report.get("evidence", {}) if isinstance(report, dict) else {}
        web = evidence.get("web", {}) if isinstance(evidence, dict) else {}
        search = evidence.get("search", {}) if isinstance(evidence, dict) else {}
        transactions = evidence.get("transactions", []) if isinstance(evidence, dict) else []
        discovered = evidence.get("discovered", {}) if isinstance(evidence, dict) else {}
        key_findings = evidence.get("key_findings", {}) if isinstance(evidence, dict) else {}
        attack_txs = key_findings.get("attack_txs", []) if isinstance(key_findings, dict) else []
        report_links = (
            key_findings.get("report_links", []) if isinstance(key_findings, dict) else []
        )
        pages = web.get("pages", []) if isinstance(web, dict) else []
        page_errors = web.get("errors", []) if isinstance(web, dict) else []
        search_queries = search.get("queries", []) if isinstance(search, dict) else []
        search_errors = search.get("errors", []) if isinstance(search, dict) else []
        return {
            "round": round_index,
            "slug": target.slug,
            "label": target.label,
            "chain": target.chain,
            "status": "ok",
            "case_id": str(report.get("case_id", "")).strip(),
            "target_address": str(discovered.get("target_address", "")).strip(),
            "case_link": str(key_findings.get("case_link", "")).strip(),
            "first_attack_tx": str(attack_txs[0]).strip() if attack_txs else "",
            "attack_tx_confidence": str(key_findings.get("attack_tx_confidence", "")).strip(),
            "attack_tx_count": len(attack_txs) if isinstance(attack_txs, list) else 0,
            "pages": len(pages) if isinstance(pages, list) else 0,
            "txs": len(transactions) if isinstance(transactions, list) else 0,
            "report_links": len(report_links) if isinstance(report_links, list) else 0,
            "search_queries": len(search_queries) if isinstance(search_queries, list) else 0,
            "web_errors": len(page_errors) if isinstance(page_errors, list) else 0,
            "search_errors": len(search_errors) if isinstance(search_errors, list) else 0,
            "report_path": str(report_path),
            "output_dir": str(output_dir),
            "error": "",
        }

    def _build_error_row(
        self,
        *,
        round_index: int,
        target: LiveScrapeBatchTarget,
        output_dir: Path,
        error: str,
    ) -> dict[str, Any]:
        return {
            "round": round_index,
            "slug": target.slug,
            "label": target.label,
            "chain": target.chain,
            "status": "error",
            "case_id": "",
            "target_address": "",
            "case_link": "",
            "first_attack_tx": "",
            "attack_tx_confidence": "",
            "attack_tx_count": 0,
            "pages": 0,
            "txs": 0,
            "report_links": 0,
            "search_queries": 0,
            "web_errors": 0,
            "search_errors": 0,
            "report_path": "",
            "output_dir": str(output_dir),
            "error": error,
        }

    def run(
        self,
        *,
        targets: Sequence[LiveScrapeBatchTarget],
        output_dir: Path | None = None,
        name: str = "live-scrape-overnight",
        poll_interval_seconds: float = 3600.0,
        duration_seconds: float | None = None,
        max_rounds: int = 0,
        per_target_sleep_seconds: float = 0.0,
    ) -> dict[str, Any]:
        batch_dir = (
            output_dir.resolve() if output_dir is not None else self.default_output_dir(name=name)
        )
        batch_dir.mkdir(parents=True, exist_ok=True)
        rounds_dir = batch_dir / "rounds"
        latest_dir = batch_dir / "latest_reports"
        rounds_dir.mkdir(parents=True, exist_ok=True)
        latest_dir.mkdir(parents=True, exist_ok=True)

        normalized_duration = (
            None
            if duration_seconds is None or float(duration_seconds) <= 0
            else float(duration_seconds)
        )
        normalized_max_rounds = max(int(max_rounds), 0)
        normalized_round_interval = max(float(poll_interval_seconds), 0.0)
        normalized_per_target_sleep = max(float(per_target_sleep_seconds), 0.0)

        manifest_path = batch_dir / "batch.json"
        latest_summary_json = batch_dir / "latest_summary.json"
        latest_summary_csv = batch_dir / "latest_summary.csv"
        latest_summary_md = batch_dir / "latest_summary.md"
        started_at = _utc_now_iso()
        manifest: dict[str, Any] = {
            "task": "live_scrape_batch",
            "source": "live_web",
            "runner": {
                "name": "live_scrape_batch_runner",
                "mode": (
                    "continuous"
                    if normalized_duration is not None or normalized_max_rounds != 1
                    else "single_round"
                ),
            },
            "batch_name": name,
            "batch_dir": str(batch_dir),
            "status": "running",
            "started_at": started_at,
            "finished_at": "",
            "poll_interval_seconds": normalized_round_interval,
            "duration_seconds": normalized_duration,
            "max_rounds": normalized_max_rounds or None,
            "per_target_sleep_seconds": normalized_per_target_sleep,
            "latest_summary_json": str(latest_summary_json),
            "latest_summary_csv": str(latest_summary_csv),
            "latest_summary_md": str(latest_summary_md),
            "targets": [target.to_manifest_payload() for target in targets],
            "rounds": [],
        }
        _write_json(manifest_path, manifest)

        start_monotonic = time.monotonic()
        round_index = 0
        status = "completed"

        try:
            while True:
                if normalized_max_rounds and round_index >= normalized_max_rounds:
                    break
                if (
                    normalized_duration is not None
                    and round_index > 0
                    and (time.monotonic() - start_monotonic) >= normalized_duration
                ):
                    break

                round_index += 1
                round_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                round_dir = rounds_dir / f"{round_index:04d}_{round_stamp}"
                round_dir.mkdir(parents=True, exist_ok=True)
                round_rows: list[dict[str, Any]] = []
                round_started_at = _utc_now_iso()
                print(
                    f"[live-scrape-batch] round={round_index} started_at={round_started_at} targets={len(targets)}",
                    flush=True,
                )

                for target_index, target in enumerate(targets, 1):
                    target_dir = round_dir / target.slug
                    target_dir.mkdir(parents=True, exist_ok=True)
                    print(
                        f"[live-scrape-batch] round={round_index} target={target.slug} start "
                        f"chain={target.chain or '-'} urls={len(target.urls)} queries={len(target.queries)}",
                        flush=True,
                    )
                    try:
                        agent = LiveScrapeAgent(
                            self.base_dir,
                            max_transactions=target.max_transactions or self.max_transactions,
                            url_timeout=self.url_timeout,
                        )
                        report = agent.build_report(
                            chain=target.chain,
                            address=target.address,
                            tx_hashes=target.tx_hashes,
                            urls=target.urls,
                            queries=target.queries,
                            search_domains=target.search_domains,
                            search_limit=target.search_limit,
                            block=target.block,
                            output_dir=target_dir,
                        )
                        report_path = target_dir / "report.json"
                        _write_json(report_path, report)
                        _write_json(latest_dir / f"{target.slug}.json", report)
                        row = self._build_summary_row(
                            round_index=round_index,
                            target=target,
                            report=report,
                            report_path=report_path,
                            output_dir=target_dir,
                        )
                        round_rows.append(row)
                        print(
                            f"[live-scrape-batch] round={round_index} target={target.slug} done "
                            f"pages={row['pages']} attack_txs={row['attack_tx_count']} "
                            f"target_address={row['target_address'] or '-'}",
                            flush=True,
                        )
                    except KeyboardInterrupt:
                        raise
                    except Exception as exc:
                        error_payload = {
                            "target": target.to_manifest_payload(),
                            "round": round_index,
                            "error": f"{type(exc).__name__}: {exc}",
                            "generated_at": _utc_now_iso(),
                        }
                        _write_json(target_dir / "error.json", error_payload)
                        row = self._build_error_row(
                            round_index=round_index,
                            target=target,
                            output_dir=target_dir,
                            error=error_payload["error"],
                        )
                        round_rows.append(row)
                        print(
                            f"[live-scrape-batch] round={round_index} target={target.slug} error={row['error']}",
                            flush=True,
                        )

                    if normalized_per_target_sleep > 0 and target_index < len(targets):
                        time.sleep(normalized_per_target_sleep)

                round_summary_json = round_dir / "round_summary.json"
                round_summary_csv = round_dir / "round_summary.csv"
                round_summary_md = round_dir / "round_summary.md"
                _write_json(round_summary_json, round_rows)
                _write_csv(round_summary_csv, round_rows)
                _write_markdown(round_summary_md, round_rows)
                _write_json(latest_summary_json, round_rows)
                _write_csv(latest_summary_csv, round_rows)
                _write_markdown(latest_summary_md, round_rows)
                manifest["rounds"].append(
                    {
                        "round": round_index,
                        "started_at": round_started_at,
                        "finished_at": _utc_now_iso(),
                        "round_dir": str(round_dir),
                        "summary_json": str(round_summary_json),
                        "summary_csv": str(round_summary_csv),
                        "summary_md": str(round_summary_md),
                        "ok": sum(1 for row in round_rows if row.get("status") == "ok"),
                        "errors": sum(1 for row in round_rows if row.get("status") != "ok"),
                        "targets": round_rows,
                    }
                )
                _write_json(manifest_path, manifest)
                print(
                    f"[live-scrape-batch] round={round_index} completed ok="
                    f"{sum(1 for row in round_rows if row.get('status') == 'ok')} "
                    f"errors={sum(1 for row in round_rows if row.get('status') != 'ok')}",
                    flush=True,
                )

                if normalized_max_rounds and round_index >= normalized_max_rounds:
                    break
                if (
                    normalized_duration is not None
                    and (time.monotonic() - start_monotonic) >= normalized_duration
                ):
                    break
                if normalized_round_interval > 0:
                    print(
                        f"[live-scrape-batch] sleeping_seconds={normalized_round_interval}",
                        flush=True,
                    )
                    time.sleep(normalized_round_interval)
        except KeyboardInterrupt:
            status = "interrupted"

        manifest["status"] = status
        manifest["finished_at"] = _utc_now_iso()
        _write_json(manifest_path, manifest)
        return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a batch of live scrape targets over repeated rounds"
    )
    parser.add_argument(
        "--config", type=Path, required=True, help="Path to a JSON list of live scrape targets"
    )
    parser.add_argument(
        "--only", action="append", default=[], help="Optional target slug filter; repeatable"
    )
    parser.add_argument("--name", default="live-scrape-overnight", help="Batch session name")
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0.0,
        help="Wall-clock duration; 0 means no time limit",
    )
    parser.add_argument(
        "--poll-interval-seconds", type=float, default=3600.0, help="Pause between rounds"
    )
    parser.add_argument(
        "--per-target-sleep-seconds",
        type=float,
        default=2.0,
        help="Pause between targets inside a round",
    )
    parser.add_argument("--max-rounds", type=int, default=0, help="Round limit; 0 means no limit")
    parser.add_argument(
        "--max-transactions", type=int, default=3, help="Default per-target tx follow limit"
    )
    parser.add_argument(
        "--url-timeout", type=int, default=20, help="Per-request timeout in seconds"
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--output-dir", type=Path, default=None, help="Explicit batch output directory"
    )
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    targets = load_batch_targets(args.config.resolve(), only=args.only)
    runner = LiveScrapeBatchRunner(
        base_dir, max_transactions=args.max_transactions, url_timeout=args.url_timeout
    )
    batch_dir = (
        args.output_dir.resolve()
        if args.output_dir is not None
        else runner.default_output_dir(name=args.name)
    )
    manifest = runner.run(
        targets=targets,
        output_dir=batch_dir,
        name=args.name,
        poll_interval_seconds=args.poll_interval_seconds,
        duration_seconds=args.duration_seconds,
        max_rounds=args.max_rounds,
        per_target_sleep_seconds=args.per_target_sleep_seconds,
    )
    print(f"[live-scrape-batch] batch_dir={batch_dir}")
    print(f"[live-scrape-batch] manifest={batch_dir / 'batch.json'}")
    print(f"[live-scrape-batch] latest_summary_json={batch_dir / 'latest_summary.json'}")
    print(f"[live-scrape-batch] latest_summary_csv={batch_dir / 'latest_summary.csv'}")
    print(f"[live-scrape-batch] latest_summary_md={batch_dir / 'latest_summary.md'}")
    print(f"[live-scrape-batch] status={manifest.get('status', '')}")
    print(f"[live-scrape-batch] rounds={len(manifest.get('rounds', []))}")


if __name__ == "__main__":
    main()
