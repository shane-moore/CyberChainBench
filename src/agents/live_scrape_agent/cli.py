"""CLI for the live scrape agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent import LiveScrapeAgent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the live scrape agent against search queries, URLs, and on-chain targets"
    )
    parser.add_argument("--chain", default="", help="Normalized chain name, e.g. ethereum or bsc")
    parser.add_argument("--address", default="", help="Primary contract address to inspect")
    parser.add_argument(
        "--tx-hash", action="append", default=[], help="Transaction hash to fetch; repeatable"
    )
    parser.add_argument(
        "--url", action="append", default=[], help="Incident or reference URL to fetch; repeatable"
    )
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        help="Web search query to expand into live URLs; repeatable",
    )
    parser.add_argument(
        "--search-domain",
        action="append",
        default=[],
        help="Optional site filter such as rekt.news; repeatable",
    )
    parser.add_argument(
        "--search-limit",
        type=int,
        default=5,
        help="Max search results to keep per query/domain combination",
    )
    parser.add_argument("--block", type=int, default=None, help="Optional historical block number")
    parser.add_argument("--max-transactions", type=int, default=5, help="Max tx hashes to follow")
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run as a polling session instead of a single scrape",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=60.0,
        help="Polling interval for continuous mode",
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0.0,
        help="Continuous-mode wall clock duration; 0 means no time limit",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="Continuous-mode iteration limit; 0 means no limit",
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--output-dir", type=Path, default=None, help="Directory to store artifacts and report"
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=None,
        help="Explicit report path; defaults to <output-dir>/report.json",
    )
    parser.add_argument(
        "--prompt-out",
        type=Path,
        default=None,
        help="Explicit combined-prompt path; defaults to <output-dir>/prompt.txt",
    )
    parser.add_argument(
        "--print-prompt", action="store_true", help="Print the combined prompt to stdout"
    )
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    agent = LiveScrapeAgent(base_dir, max_transactions=args.max_transactions)
    continuous_mode = bool(args.continuous or args.duration_seconds > 0 or args.max_iterations > 0)

    if continuous_mode:
        target_dir = (
            args.output_dir.resolve()
            if args.output_dir is not None
            else agent.default_session_dir(
                chain=args.chain,
                address=args.address,
            )
        )
        session = agent.run_session(
            chain=args.chain,
            address=args.address,
            tx_hashes=args.tx_hash,
            urls=args.url,
            queries=args.query,
            search_domains=args.search_domain,
            search_limit=args.search_limit,
            block=args.block,
            output_dir=target_dir,
            poll_interval_seconds=args.poll_interval_seconds,
            duration_seconds=args.duration_seconds,
            max_iterations=args.max_iterations,
            write_prompt_bundle=bool(args.prompt_out is not None or args.print_prompt),
            latest_prompt_path=args.prompt_out,
            session_manifest_path=args.report_out,
        )
        manifest_path = (
            args.report_out.resolve()
            if args.report_out is not None
            else target_dir / "session.json"
        )
        latest_report_path = target_dir / "latest_report.json"
        latest_prompt_path = (
            args.prompt_out.resolve()
            if args.prompt_out is not None
            else target_dir / "latest_prompt.txt"
        )
        print(f"[live-scrape-agent] session_dir={target_dir}")
        print(f"[live-scrape-agent] session_manifest={manifest_path}")
        print(f"[live-scrape-agent] latest_report={latest_report_path}")
        if args.prompt_out is not None or args.print_prompt:
            print(f"[live-scrape-agent] latest_prompt={latest_prompt_path}")
        print(f"[live-scrape-agent] status={session.get('status', '')}")
        print(f"[live-scrape-agent] iterations={len(session.get('iterations', []))}")
        if session.get("iterations"):
            latest = session["iterations"][-1]
            print(f"[live-scrape-agent] pages={latest.get('pages', 0)}")
            print(f"[live-scrape-agent] txs={latest.get('txs', 0)}")
            print(f"[live-scrape-agent] target_address={latest.get('target_address', '')}")
        if args.print_prompt and latest_prompt_path.exists():
            print("===== live-scrape-agent prompt =====")
            print(latest_prompt_path.read_text(encoding="utf-8").rstrip())
        return

    target_dir = (
        args.output_dir.resolve()
        if args.output_dir is not None
        else agent.default_output_dir(
            chain=args.chain,
            address=args.address,
        )
    )
    report = agent.build_report(
        chain=args.chain,
        address=args.address,
        tx_hashes=args.tx_hash,
        urls=args.url,
        queries=args.query,
        search_domains=args.search_domain,
        search_limit=args.search_limit,
        block=args.block,
        output_dir=target_dir,
    )

    report_path = (
        args.report_out.resolve() if args.report_out is not None else target_dir / "report.json"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if args.prompt_out is not None or args.print_prompt:
        prompt_bundle = agent.build_prompt_bundle(
            chain=args.chain,
            address=args.address,
            tx_hashes=args.tx_hash,
            urls=args.url,
            queries=args.query,
            search_domains=args.search_domain,
            search_limit=args.search_limit,
            block=args.block,
            report=report,
        )
        prompt_path = (
            args.prompt_out.resolve() if args.prompt_out is not None else target_dir / "prompt.txt"
        )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt_bundle["combined_prompt"], encoding="utf-8")
        if args.print_prompt:
            print("===== live-scrape-agent prompt =====")
            print(prompt_bundle["combined_prompt"].rstrip())

    print(f"[live-scrape-agent] output_dir={target_dir}")
    print(f"[live-scrape-agent] report={report_path}")
    if args.prompt_out is not None or args.print_prompt:
        print(f"[live-scrape-agent] prompt={prompt_path}")
    evidence = report.get("evidence", {})
    search = evidence.get("search", {}) if isinstance(evidence, dict) else {}
    web = evidence.get("web", {}) if isinstance(evidence, dict) else {}
    transactions = evidence.get("transactions", []) if isinstance(evidence, dict) else []
    discovered = evidence.get("discovered", {}) if isinstance(evidence, dict) else {}
    print(f"[live-scrape-agent] search_queries={len(search.get('queries', []))}")
    print(f"[live-scrape-agent] pages={len(web.get('pages', []))}")
    print(f"[live-scrape-agent] txs={len(transactions) if isinstance(transactions, list) else 0}")
    print(f"[live-scrape-agent] target_address={discovered.get('target_address', '')}")


if __name__ == "__main__":
    main()
