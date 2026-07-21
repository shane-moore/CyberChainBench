"""Deterministic live scraper for web search, incident pages, and on-chain evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

from infra.chain.metadata import (
    lookup_address_transaction_traces,
    lookup_address_transactions,
    lookup_contract_creation,
    lookup_proxy_info,
    lookup_runtime_artifacts,
    lookup_transaction,
    lookup_transaction_receipt,
    lookup_verified_source,
)
from prompts.live_scrape import LIVE_SCRAPE_AGENT_PROMPT, LIVE_SCRAPE_OUTPUT_SCHEMA
from project_layout import LIVE_SCRAPE_WORKSPACE_DIR

_USER_AGENT = "web3bug-benchmark-live-scrape-agent/1.0"
_DEFAULT_SEARCH_PROVIDER = "duckduckgo_html"
_DEFAULT_SEARCH_RESULT_LIMIT = 5
_EXPLORER_MARKERS = (
    "etherscan.io",
    "bscscan.com",
    "arbiscan.io",
    "basescan.org",
    "snowtrace.io",
    "ftmscan.com",
    "polygonscan.com",
    "optimistic.etherscan.io",
    "gnosisscan.io",
    "blastscan.io",
    "celoscan.io",
    "lineascan.build",
)
_DEBUG_MARKERS = (
    "phalcon.blocksec.com",
    "app.blocksec.com",
    "dashboard.tenderly.co",
    "tenderly.co",
)
_REPORT_STRONG_HINTS = (
    "report",
    "postmortem",
    "post-mortem",
    "root cause",
    "analysis",
    "recovery",
    "rekt",
)
_REPORT_HINTS = (
    "incident",
    "exploit",
    "hack",
    "attack",
)
_ATTACK_TX_HINTS = (
    "attack tx",
    "attack transaction",
    "exploit tx",
    "exploit transaction",
    "hack tx",
    "hack transaction",
    "attacker",
    "malicious transaction",
    "transaction hash",
    "tx 1",
    "tx1",
)
_ADDRESS_HINTS = (
    "target",
    "victim",
    "vulnerable",
    "contract",
    "pool",
    "vault",
    "proxy",
    "attacker",
)
_SEARCH_RESULT_LINK_RE = re.compile(
    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_SEARCH_RESULT_SNIPPET_RE = re.compile(
    r'<(?:a|div)[^>]*class="result__snippet"[^>]*>(.*?)</(?:a|div)>',
    re.IGNORECASE | re.DOTALL,
)
_SEARCH_RESULT_DISPLAY_URL_RE = re.compile(
    r'<a[^>]*class="result__url"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_URL_RE = re.compile(r"https?://[^\s<>'\"()\\]+")
_TX_HASH_RE = re.compile(r"(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])")
_ADDRESS_RE = re.compile(r"(?<![a-fA-F0-9])0x[a-fA-F0-9]{40}(?![a-fA-F0-9])")
_TEXT_BREAK_TAGS = {
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
}
_SKIP_TEXT_TAGS = {"script", "style", "noscript", "svg"}


class _HTMLTextExtractor(HTMLParser):
    """Small HTML-to-text normalizer without external dependencies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = str(tag).lower()
        if tag_name in _SKIP_TEXT_TAGS:
            self._skip_depth += 1
            return
        if tag_name in _TEXT_BREAK_TAGS:
            self._parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if str(tag).lower() in _TEXT_BREAK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag_name = str(tag).lower()
        if tag_name in _SKIP_TEXT_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if tag_name in _TEXT_BREAK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        text = str(data).replace("\xa0", " ")
        if not text.strip():
            return
        self._parts.append(text)

    def get_text(self) -> str:
        text = "".join(self._parts)
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r" *\n *", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


class _HTMLLinkExtractor(HTMLParser):
    """Collect anchor links and labels from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._current_href = ""
        self._current_parts: list[str] = []
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if str(tag).lower() != "a":
            return
        href = ""
        for key, value in attrs:
            if str(key).lower() == "href":
                href = str(value or "").strip()
                break
        self._current_href = href
        self._current_parts = []

    def handle_data(self, data: str) -> None:
        if not self._current_href:
            return
        text = str(data).strip()
        if text:
            self._current_parts.append(text)

    def handle_endtag(self, tag: str) -> None:
        if str(tag).lower() != "a" or not self._current_href:
            return
        self.links.append(
            {
                "href": self._current_href,
                "label": " ".join(self._current_parts).strip(),
            }
        )
        self._current_href = ""
        self._current_parts = []


def _dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _safe_name(value: str, fallback: str) -> str:
    text = "".join(
        ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in str(value).strip()
    )
    text = "-".join(part for part in text.split("-") if part)
    return text or fallback


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _clean_fragment(fragment: str) -> str:
    text = unescape(str(fragment))
    text = _TAG_RE.sub(" ", text)
    text = text.replace("\xa0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _clean_url(url: str) -> str:
    cleaned = unescape(str(url).strip())
    cleaned = cleaned.rstrip(".,;:!?)]}\"'")
    return cleaned


def _is_http_url(value: str) -> bool:
    lowered = str(value).strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _is_explorer_url(value: str) -> bool:
    lowered = str(value).strip().lower()
    return (
        any(marker in lowered for marker in _EXPLORER_MARKERS)
        or "/tx/" in lowered
        or "/address/" in lowered
    )


def _is_debug_url(value: str) -> bool:
    lowered = str(value).strip().lower()
    return any(marker in lowered for marker in _DEBUG_MARKERS)


def _extract_urls_from_text(text: str) -> list[str]:
    return _dedupe_keep_order(_clean_url(item) for item in _URL_RE.findall(text or ""))


def _extract_url_entries_from_text(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    source_text = str(text or "")
    for match in _URL_RE.finditer(source_text):
        url = _clean_url(match.group(0))
        if not _is_http_url(url) or url in seen:
            continue
        seen.add(url)
        out.append(
            {
                "url": url,
                "context": _context_snippet(source_text, match.start(), match.end(), radius=40),
            }
        )
    return out


def _extract_links_from_html(text: str) -> list[dict[str, str]]:
    if not _looks_like_html(text):
        return []
    parser = _HTMLLinkExtractor()
    parser.feed(text)
    parser.close()
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in parser.links:
        href = _resolve_search_result_url(item.get("href", ""))
        if not _is_http_url(href) or href in seen:
            continue
        seen.add(href)
        out.append(
            {
                "url": href,
                "label": _clean_fragment(item.get("label", "")),
            }
        )
    return out


def _contains_hint(text: str, hints: Iterable[str]) -> bool:
    lowered = str(text).strip().lower()
    return any(str(hint).lower() in lowered for hint in hints)


def _context_snippet(text: str, start: int, end: int, *, radius: int = 80) -> str:
    snippet = str(text)[max(0, start - radius) : min(len(str(text)), end + radius)]
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet.strip()


def _top_scored(
    items: Iterable[dict[str, Any]], *, value_key: str, limit: int = 5
) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        value = str(item.get(value_key, "")).strip()
        if not value:
            continue
        current = deduped.get(value)
        score = int(item.get("score", 0))
        if current is None or score > int(current.get("score", 0)):
            deduped[value] = item
    ranked = sorted(
        deduped.values(),
        key=lambda item: (-int(item.get("score", 0)), str(item.get(value_key, ""))),
    )
    return ranked[: max(int(limit), 1)]


def _tx_hash_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url).strip())
    parts = [part for part in parsed.path.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "tx":
            candidate = parts[index + 1]
            if _TX_HASH_RE.fullmatch(candidate):
                return candidate
    return ""


def _address_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url).strip())
    parts = [part for part in parsed.path.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "address":
            candidate = parts[index + 1]
            if _ADDRESS_RE.fullmatch(candidate):
                return candidate
    return ""


def _looks_like_html(text: str) -> bool:
    lowered = str(text).lower()
    return any(
        marker in lowered
        for marker in ("<!doctype html", "<html", "<body", "<div", "<p", "<article")
    )


def _normalize_page_text(raw_text: str) -> str:
    text = str(raw_text)
    if _looks_like_html(text):
        parser = _HTMLTextExtractor()
        parser.feed(text)
        parser.close()
        normalized = parser.get_text()
        if normalized:
            return normalized
    text = unescape(text).replace("\xa0", " ")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_html_title(raw_text: str) -> str:
    source = str(raw_text or "")
    if not _looks_like_html(source):
        return ""
    match = _TITLE_RE.search(source)
    if not match:
        return ""
    return _clean_fragment(match.group(1))


def _resolve_search_result_url(url: str) -> str:
    href = unescape(str(url).strip())
    if not href:
        return ""
    if href.startswith("//"):
        href = f"https:{href}"
    parsed = urllib.parse.urlparse(href)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path == "/l/":
        target = urllib.parse.parse_qs(parsed.query).get("uddg", [""])[0]
        href = str(target).strip()
    parsed = urllib.parse.urlparse(href)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    if not parsed.scheme and not parsed.netloc:
        return ""
    return href


def _search_source_tag(query: str, domain: str = "") -> str:
    if domain:
        return f"search:{query} site:{domain}"
    return f"search:{query}"


def _normalize_query_seed(value: str) -> str:
    text = _clean_fragment(value)
    for separator in (" | ", " - ", " — ", " – ", ": "):
        if separator in text:
            head = text.split(separator, 1)[0].strip()
            if len(head) >= 4:
                text = head
                break
    text = re.sub(r"\brekt\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpost-?mortem\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bincident\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\broot cause analysis\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\brecovery\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip(" -|:")
    return text


def _query_seed_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url).strip())
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if not parts:
        return ""
    candidate = parts[-1]
    if "." in candidate:
        candidate = candidate.rsplit(".", 1)[0]
    candidate = candidate.replace("-", " ").replace("_", " ")
    return _normalize_query_seed(candidate)


def _derive_attack_tx_fallback_queries(
    *, requested_urls: Iterable[str], page_titles: Iterable[str]
) -> list[str]:
    seeds = _dedupe_keep_order(
        [
            *(_normalize_query_seed(title) for title in page_titles),
            *(_query_seed_from_url(url) for url in requested_urls),
        ]
    )
    queries: list[str] = []
    for seed in seeds:
        if len(seed) < 4:
            continue
        queries.extend(
            [
                f"{seed} attack tx",
                f"{seed} exploit tx",
                f"{seed} transaction hash",
            ]
        )
        if len(queries) >= 6:
            break
    return _dedupe_keep_order(queries)[:6]


def _default_case_id(
    *,
    address: str = "",
    tx_hashes: Iterable[str] = (),
    queries: Iterable[str] = (),
    urls: Iterable[str] = (),
) -> str:
    normalized_address = str(address).strip()
    if normalized_address:
        return normalized_address
    for tx_hash in tx_hashes:
        normalized = str(tx_hash).strip()
        if normalized:
            return normalized
    for query in queries:
        normalized = _safe_name(str(query).strip(), "")
        if normalized:
            return normalized
    for url in urls:
        normalized = _safe_name(str(url).strip(), "")
        if normalized:
            return normalized
    return "live-scrape"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _report_stats(report: dict[str, Any]) -> dict[str, Any]:
    evidence = report.get("evidence", {}) if isinstance(report, dict) else {}
    search = evidence.get("search", {}) if isinstance(evidence, dict) else {}
    web = evidence.get("web", {}) if isinstance(evidence, dict) else {}
    transactions = evidence.get("transactions", []) if isinstance(evidence, dict) else []
    discovered = evidence.get("discovered", {}) if isinstance(evidence, dict) else {}
    return {
        "search_queries": len(search.get("queries", [])) if isinstance(search, dict) else 0,
        "pages": len(web.get("pages", [])) if isinstance(web, dict) else 0,
        "txs": len(transactions) if isinstance(transactions, list) else 0,
        "target_address": (
            str(discovered.get("target_address", "")).strip()
            if isinstance(discovered, dict)
            else ""
        ),
        "case_id": str(report.get("case_id", "")).strip() if isinstance(report, dict) else "",
    }


def _fetch_url_document(url: str, *, timeout: int) -> dict[str, Any]:
    current_url = str(url).strip()
    seen: set[str] = set()
    while True:
        request = urllib.request.Request(current_url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
                headers = getattr(response, "headers", None)
                content_type = ""
                if headers is not None and hasattr(headers, "get_content_type"):
                    content_type = str(headers.get_content_type() or "").strip()
                final_url = str(getattr(response, "url", current_url)).strip() or current_url
                status = getattr(response, "status", None)
            return {
                "url": str(url).strip(),
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "raw_text": raw_text,
                "title": _extract_html_title(raw_text),
                "text": _normalize_page_text(raw_text),
            }
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise
            location = str(exc.headers.get("Location", "")).strip()
            if not location:
                raise
            next_url = urllib.parse.urljoin(current_url, location)
            if next_url in seen:
                raise
            seen.add(current_url)
            current_url = next_url


def _parse_duckduckgo_search_results(html_text: str, *, limit: int) -> list[dict[str, Any]]:
    links = _SEARCH_RESULT_LINK_RE.findall(html_text)
    snippets = _SEARCH_RESULT_SNIPPET_RE.findall(html_text)
    display_urls = _SEARCH_RESULT_DISPLAY_URL_RE.findall(html_text)

    results: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for index, (href, title_fragment) in enumerate(links, 1):
        url = _resolve_search_result_url(href)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        snippet_fragment = snippets[index - 1] if index - 1 < len(snippets) else ""
        display_fragment = display_urls[index - 1] if index - 1 < len(display_urls) else ""
        results.append(
            {
                "rank": len(results) + 1,
                "url": url,
                "title": _clean_fragment(title_fragment),
                "display_url": _clean_fragment(display_fragment) or url,
                "snippet": _clean_fragment(snippet_fragment),
            }
        )
        if len(results) >= max(int(limit), 1):
            break
    return results


def _score_report_link(url: str, *, text: str = "", source_kind: str = "") -> int:
    score = 0
    if _is_http_url(url):
        score += 1
    if not _is_explorer_url(url) and not _is_debug_url(url):
        score += 2
    if _contains_hint(url, _REPORT_STRONG_HINTS) or _contains_hint(text, _REPORT_STRONG_HINTS):
        score += 7
    if _contains_hint(url, _REPORT_HINTS) or _contains_hint(text, _REPORT_HINTS):
        score += 3
    if source_kind in {"search_result", "page_url", "input_url"}:
        score += 2
    return score


def _score_attack_tx(*, context: str = "", source_kind: str = "", url: str = "") -> int:
    score = 1
    if _contains_hint(context, _ATTACK_TX_HINTS):
        score += 5
    if source_kind in {"explorer_url", "page_text"}:
        score += 2
    if "/tx/" in str(url).lower():
        score += 2
    return score


def _score_address(
    *, context: str = "", source_kind: str = "", is_target: bool = False, url: str = ""
) -> int:
    score = 1
    if is_target:
        score += 6
    if _contains_hint(context, _ADDRESS_HINTS):
        score += 3
    if source_kind in {"explorer_url", "page_text"}:
        score += 1
    if "/address/" in str(url).lower():
        score += 2
    return score


class LiveScrapeAgent:
    """Collect live incident evidence from search results, URLs, and chain lookups."""

    def __init__(self, base_dir: Path, *, max_transactions: int = 5, url_timeout: int = 20):
        self.base_dir = base_dir.resolve()
        self.max_transactions = max(int(max_transactions), 1)
        self.url_timeout = max(int(url_timeout), 1)

    def default_output_dir(self, *, chain: str = "", address: str = "") -> Path:
        slug = _safe_name(
            f"{chain}-{address}" if chain or address else "live-scrape", "live-scrape"
        )
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.base_dir / LIVE_SCRAPE_WORKSPACE_DIR / "reports" / f"{stamp}_{slug}"

    def default_session_dir(self, *, chain: str = "", address: str = "") -> Path:
        slug = _safe_name(
            f"{chain}-{address}" if chain or address else "live-scrape-session",
            "live-scrape-session",
        )
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.base_dir / LIVE_SCRAPE_WORKSPACE_DIR / "reports" / f"{stamp}_{slug}_session"

    def _run_search(
        self,
        *,
        query: str,
        domain: str = "",
        limit: int = _DEFAULT_SEARCH_RESULT_LIMIT,
    ) -> dict[str, Any]:
        effective_query = str(query).strip()
        normalized_domain = str(domain).strip()
        if normalized_domain:
            effective_query = f"{effective_query} site:{normalized_domain}"
        encoded_query = urllib.parse.urlencode({"q": effective_query})
        search_url = f"https://duckduckgo.com/html/?{encoded_query}"
        html_text = _fetch_url_document(search_url, timeout=self.url_timeout)["raw_text"]
        results = _parse_duckduckgo_search_results(html_text, limit=limit)
        return {
            "provider": _DEFAULT_SEARCH_PROVIDER,
            "query": str(query).strip(),
            "domain": normalized_domain,
            "effective_query": effective_query,
            "search_url": search_url,
            "raw_html": html_text,
            "results": results,
        }

    def build_report(
        self,
        *,
        chain: str = "",
        address: str = "",
        tx_hashes: Iterable[str] = (),
        urls: Iterable[str] = (),
        queries: Iterable[str] = (),
        search_domains: Iterable[str] = (),
        search_limit: int = _DEFAULT_SEARCH_RESULT_LIMIT,
        block: int | None = None,
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        target_dir = (
            output_dir.resolve()
            if output_dir is not None
            else self.default_output_dir(chain=chain, address=address)
        )
        target_dir.mkdir(parents=True, exist_ok=True)

        normalized_chain = str(chain).strip()
        requested_address = str(address).strip()
        requested_urls = _dedupe_keep_order(urls)
        requested_txs = _dedupe_keep_order(tx_hashes)
        requested_queries = _dedupe_keep_order(queries)
        normalized_domains = _dedupe_keep_order(search_domains)
        normalized_search_limit = max(int(search_limit), 1)

        search_reports: list[dict[str, Any]] = []
        search_errors: list[dict[str, str]] = []
        discovered_search_urls: list[str] = []
        link_candidates: list[dict[str, Any]] = []
        attack_tx_candidates: list[dict[str, Any]] = []
        address_candidates: list[dict[str, Any]] = []
        url_sources: dict[str, list[str]] = {url: ["input_url"] for url in requested_urls}
        search_dir = target_dir / "search"
        domain_scope = normalized_domains or [""]
        for query_index, query in enumerate(requested_queries, 1):
            for domain in domain_scope:
                try:
                    search_report = self._run_search(
                        query=query,
                        domain=domain,
                        limit=normalized_search_limit,
                    )
                except (OSError, urllib.error.URLError) as exc:
                    search_errors.append(
                        {
                            "query": query,
                            "domain": domain,
                            "error": str(exc),
                        }
                    )
                    continue

                slug_parts = [f"{query_index:02d}", _safe_name(query, "query")]
                if domain:
                    slug_parts.append(_safe_name(domain, "domain"))
                slug = "_".join(slug_parts)
                html_path = search_dir / f"{slug}.html"
                json_path = search_dir / f"{slug}.json"
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_text = str(search_report.get("raw_html", ""))
                html_path.write_text(html_text, encoding="utf-8")

                stored_report = dict(search_report)
                stored_report.pop("raw_html", None)
                stored_report["html_path"] = str(html_path)
                stored_report["results_path"] = str(json_path)
                _write_json(json_path, stored_report)
                search_reports.append(stored_report)

                source_tag = _search_source_tag(query, domain)
                for item in search_report.get("results", []):
                    result_url = str(item.get("url", "")).strip()
                    if not result_url:
                        continue
                    discovered_search_urls.append(result_url)
                    url_sources.setdefault(result_url, []).append(source_tag)
                    link_candidates.append(
                        {
                            "url": result_url,
                            "label": str(item.get("title", "")).strip(),
                            "context": " ".join(
                                part
                                for part in [
                                    str(item.get("title", "")).strip(),
                                    str(item.get("snippet", "")).strip(),
                                ]
                                if part
                            ),
                            "source_kind": "search_result",
                            "source_tag": source_tag,
                        }
                    )

        combined_urls = _dedupe_keep_order([*requested_urls, *discovered_search_urls])

        page_reports: list[dict[str, Any]] = []
        page_tx_hashes: list[str] = []
        page_addresses: list[str] = []
        page_errors: list[dict[str, Any]] = []
        page_titles: list[str] = []
        pages_dir = target_dir / "pages"
        for index, url in enumerate(combined_urls, 1):
            try:
                document = _fetch_url_document(url, timeout=self.url_timeout)
            except (OSError, urllib.error.URLError) as exc:
                page_errors.append(
                    {"url": url, "source_tags": url_sources.get(url, []), "error": str(exc)}
                )
                continue

            raw_text = str(document.get("raw_text", ""))
            normalized_text = str(document.get("text", "")).strip()
            page_title = str(document.get("title", "")).strip()
            extracted_text_urls = _extract_url_entries_from_text(normalized_text)
            extracted_html_links = _extract_links_from_html(raw_text)
            looks_like_html = _looks_like_html(raw_text)
            raw_suffix = ".html" if looks_like_html else ".txt"
            raw_path = pages_dir / f"page_{index:02d}.raw{raw_suffix}"
            page_path = pages_dir / f"page_{index:02d}.txt"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(
                raw_text if raw_text.endswith("\n") else raw_text + "\n", encoding="utf-8"
            )
            page_path.write_text(
                normalized_text + ("\n" if normalized_text else ""), encoding="utf-8"
            )

            extracted_txs = _dedupe_keep_order(_TX_HASH_RE.findall(normalized_text))
            extracted_addresses = _dedupe_keep_order(_ADDRESS_RE.findall(normalized_text))
            page_tx_hashes.extend(extracted_txs)
            page_addresses.extend(extracted_addresses)
            if page_title:
                page_titles.append(page_title)

            for match in _TX_HASH_RE.finditer(normalized_text):
                tx_hash = match.group(0)
                context = _context_snippet(normalized_text, match.start(), match.end())
                attack_tx_candidates.append(
                    {
                        "tx_hash": tx_hash,
                        "score": _score_attack_tx(context=context, source_kind="page_text"),
                        "context": context,
                        "source_kind": "page_text",
                        "source_url": url,
                    }
                )

            for match in _ADDRESS_RE.finditer(normalized_text):
                address_value = match.group(0)
                context = _context_snippet(normalized_text, match.start(), match.end())
                address_candidates.append(
                    {
                        "address": address_value,
                        "score": _score_address(context=context, source_kind="page_text"),
                        "context": context,
                        "source_kind": "page_text",
                        "source_url": url,
                    }
                )

            link_candidates.append(
                {
                    "url": url,
                    "label": page_title,
                    "context": "",
                    "source_kind": "page_url",
                    "source_tag": ",".join(url_sources.get(url, [])),
                }
            )
            for item in extracted_text_urls:
                link_candidates.append(
                    {
                        "url": str(item.get("url", "")).strip(),
                        "label": "",
                        "context": str(item.get("context", "")).strip(),
                        "source_kind": "page_text_url",
                        "source_tag": ",".join(url_sources.get(url, [])),
                    }
                )
            for item in extracted_html_links:
                link_candidates.append(
                    {
                        "url": str(item.get("url", "")).strip(),
                        "label": str(item.get("label", "")).strip(),
                        "context": str(item.get("label", "")).strip(),
                        "source_kind": "page_link",
                        "source_tag": ",".join(url_sources.get(url, [])),
                    }
                )

            page_reports.append(
                {
                    "url": url,
                    "final_url": document.get("final_url", url),
                    "title": page_title,
                    "path": str(page_path),
                    "raw_path": str(raw_path),
                    "source_tags": url_sources.get(url, []),
                    "content_type": str(document.get("content_type", "")).strip(),
                    "status": document.get("status"),
                    "text_length": len(normalized_text),
                    "tx_hashes": extracted_txs,
                    "addresses": extracted_addresses[:20],
                    "links": [item["url"] for item in extracted_html_links[:20]],
                }
            )

        has_direct_attack_tx = bool(
            requested_txs
            or page_tx_hashes
            or any(
                _tx_hash_from_url(str(item.get("url", "")).strip())
                for item in link_candidates
                if isinstance(item, dict)
            )
        )
        fallback_queries: list[str] = []
        if not has_direct_attack_tx and requested_urls:
            fallback_queries = _derive_attack_tx_fallback_queries(
                requested_urls=requested_urls,
                page_titles=page_titles,
            )
            fallback_discovered_urls: list[str] = []
            search_query_base = len(search_reports)
            for query_offset, query in enumerate(fallback_queries, 1):
                try:
                    search_report = self._run_search(
                        query=query,
                        domain="",
                        limit=max(normalized_search_limit, 5),
                    )
                except (OSError, urllib.error.URLError) as exc:
                    search_errors.append(
                        {
                            "query": query,
                            "domain": "",
                            "error": str(exc),
                        }
                    )
                    continue

                query_index = search_query_base + query_offset
                slug = "_".join([f"{query_index:02d}", _safe_name(query, "query")])
                html_path = search_dir / f"{slug}.html"
                json_path = search_dir / f"{slug}.json"
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_text = str(search_report.get("raw_html", ""))
                html_path.write_text(html_text, encoding="utf-8")

                stored_report = dict(search_report)
                stored_report.pop("raw_html", None)
                stored_report["html_path"] = str(html_path)
                stored_report["results_path"] = str(json_path)
                stored_report["reason"] = "attack_tx_fallback"
                _write_json(json_path, stored_report)
                search_reports.append(stored_report)

                source_tag = _search_source_tag(query)
                for item in search_report.get("results", []):
                    result_url = str(item.get("url", "")).strip()
                    if not result_url:
                        continue
                    fallback_discovered_urls.append(result_url)
                    url_sources.setdefault(result_url, []).append(source_tag)
                    link_candidates.append(
                        {
                            "url": result_url,
                            "label": str(item.get("title", "")).strip(),
                            "context": " ".join(
                                part
                                for part in [
                                    str(item.get("title", "")).strip(),
                                    str(item.get("snippet", "")).strip(),
                                ]
                                if part
                            ),
                            "source_kind": "search_result",
                            "source_tag": source_tag,
                        }
                    )

            fallback_urls = [
                url
                for url in _dedupe_keep_order(fallback_discovered_urls)
                if url not in combined_urls
            ]
            for index, url in enumerate(fallback_urls, len(page_reports) + 1):
                try:
                    document = _fetch_url_document(url, timeout=self.url_timeout)
                except (OSError, urllib.error.URLError) as exc:
                    page_errors.append(
                        {"url": url, "source_tags": url_sources.get(url, []), "error": str(exc)}
                    )
                    continue

                raw_text = str(document.get("raw_text", ""))
                normalized_text = str(document.get("text", "")).strip()
                page_title = str(document.get("title", "")).strip()
                extracted_text_urls = _extract_url_entries_from_text(normalized_text)
                extracted_html_links = _extract_links_from_html(raw_text)
                looks_like_html = _looks_like_html(raw_text)
                raw_suffix = ".html" if looks_like_html else ".txt"
                raw_path = pages_dir / f"page_{index:02d}.raw{raw_suffix}"
                page_path = pages_dir / f"page_{index:02d}.txt"
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_text(
                    raw_text if raw_text.endswith("\n") else raw_text + "\n", encoding="utf-8"
                )
                page_path.write_text(
                    normalized_text + ("\n" if normalized_text else ""), encoding="utf-8"
                )

                extracted_txs = _dedupe_keep_order(_TX_HASH_RE.findall(normalized_text))
                extracted_addresses = _dedupe_keep_order(_ADDRESS_RE.findall(normalized_text))
                page_tx_hashes.extend(extracted_txs)
                page_addresses.extend(extracted_addresses)
                if page_title:
                    page_titles.append(page_title)

                for match in _TX_HASH_RE.finditer(normalized_text):
                    tx_hash = match.group(0)
                    context = _context_snippet(normalized_text, match.start(), match.end())
                    attack_tx_candidates.append(
                        {
                            "tx_hash": tx_hash,
                            "score": _score_attack_tx(context=context, source_kind="page_text"),
                            "context": context,
                            "source_kind": "page_text",
                            "source_url": url,
                        }
                    )

                for match in _ADDRESS_RE.finditer(normalized_text):
                    address_value = match.group(0)
                    context = _context_snippet(normalized_text, match.start(), match.end())
                    address_candidates.append(
                        {
                            "address": address_value,
                            "score": _score_address(context=context, source_kind="page_text"),
                            "context": context,
                            "source_kind": "page_text",
                            "source_url": url,
                        }
                    )

                link_candidates.append(
                    {
                        "url": url,
                        "label": page_title,
                        "context": "",
                        "source_kind": "page_url",
                        "source_tag": ",".join(url_sources.get(url, [])),
                    }
                )
                for item in extracted_text_urls:
                    link_candidates.append(
                        {
                            "url": str(item.get("url", "")).strip(),
                            "label": "",
                            "context": str(item.get("context", "")).strip(),
                            "source_kind": "page_text_url",
                            "source_tag": ",".join(url_sources.get(url, [])),
                        }
                    )
                for item in extracted_html_links:
                    link_candidates.append(
                        {
                            "url": str(item.get("url", "")).strip(),
                            "label": str(item.get("label", "")).strip(),
                            "context": str(item.get("label", "")).strip(),
                            "source_kind": "page_link",
                            "source_tag": ",".join(url_sources.get(url, [])),
                        }
                    )

                page_reports.append(
                    {
                        "url": url,
                        "final_url": document.get("final_url", url),
                        "title": page_title,
                        "path": str(page_path),
                        "raw_path": str(raw_path),
                        "source_tags": url_sources.get(url, []),
                        "content_type": str(document.get("content_type", "")).strip(),
                        "status": document.get("status"),
                        "text_length": len(normalized_text),
                        "tx_hashes": extracted_txs,
                        "addresses": extracted_addresses[:20],
                        "links": [item["url"] for item in extracted_html_links[:20]],
                    }
                )

            combined_urls = _dedupe_keep_order([*combined_urls, *fallback_urls])

        combined_addresses = _dedupe_keep_order(
            ([requested_address] if requested_address else []) + page_addresses
        )
        target_address = combined_addresses[0] if combined_addresses else ""
        combined_txs = _dedupe_keep_order([*requested_txs, *page_tx_hashes])
        case_id = _default_case_id(
            address=target_address or requested_address,
            tx_hashes=combined_txs,
            queries=requested_queries,
            urls=combined_urls,
        )

        for tx_hash in requested_txs:
            attack_tx_candidates.append(
                {
                    "tx_hash": str(tx_hash).strip(),
                    "score": _score_attack_tx(source_kind="input"),
                    "context": "",
                    "source_kind": "input",
                    "source_url": "",
                }
            )
        if target_address:
            address_candidates.append(
                {
                    "address": target_address,
                    "score": _score_address(source_kind="derived_target", is_target=True),
                    "context": "derived primary target address",
                    "source_kind": "derived_target",
                    "source_url": "",
                }
            )
        for item in link_candidates:
            url_value = str(item.get("url", "")).strip()
            context = " ".join(
                part
                for part in [
                    str(item.get("label", "")).strip(),
                    str(item.get("context", "")).strip(),
                ]
                if part
            )
            tx_hash = _tx_hash_from_url(url_value)
            if tx_hash:
                attack_tx_candidates.append(
                    {
                        "tx_hash": tx_hash,
                        "score": _score_attack_tx(
                            context=context, source_kind="explorer_url", url=url_value
                        ),
                        "context": context,
                        "source_kind": "explorer_url",
                        "source_url": url_value,
                    }
                )
            address_value = _address_from_url(url_value)
            if address_value:
                address_candidates.append(
                    {
                        "address": address_value,
                        "score": _score_address(
                            context=context,
                            source_kind="explorer_url",
                            is_target=(
                                address_value.lower() == target_address.lower()
                                if target_address
                                else False
                            ),
                            url=url_value,
                        ),
                        "context": context,
                        "source_kind": "explorer_url",
                        "source_url": url_value,
                    }
                )

        on_chain: dict[str, Any] = {}
        if normalized_chain and target_address:
            proxy_info = lookup_proxy_info(normalized_chain, target_address, block)
            on_chain["proxy_info"] = proxy_info

            verified = lookup_verified_source(normalized_chain, target_address)
            verified_summary = {
                key: value for key, value in verified.items() if key != "source_files"
            }
            saved_verified: dict[str, str] = {}
            source_files = verified.get("source_files", {}) if isinstance(verified, dict) else {}
            if isinstance(source_files, dict) and source_files:
                verified_dir = target_dir / "verified_source"
                verified_dir.mkdir(parents=True, exist_ok=True)
                for filename, content in source_files.items():
                    rel_name = _safe_name(
                        str(filename).replace("/", "_").replace("\\", "_"), "source.sol"
                    )
                    out_path = verified_dir / rel_name
                    text = str(content)
                    out_path.write_text(
                        text if text.endswith("\n") else text + "\n", encoding="utf-8"
                    )
                    saved_verified[str(filename)] = str(out_path)
            if saved_verified:
                verified_summary["paths"] = saved_verified
            on_chain["verified_source"] = verified_summary

            creation = lookup_contract_creation(normalized_chain, target_address)
            creation_summary = dict(creation)
            creation_bytecode = str(creation.get("creation_bytecode", "")).strip()
            if creation_bytecode.startswith("0x") and len(creation_bytecode) > 2:
                creation_dir = target_dir / "creation"
                creation_dir.mkdir(parents=True, exist_ok=True)
                creation_path = creation_dir / "creation_bytecode.hex"
                creation_path.write_text(creation_bytecode + "\n", encoding="utf-8")
                creation_summary["paths"] = {"creation_bytecode.hex": str(creation_path)}
            on_chain["contract_creation"] = creation_summary

            runtime_artifacts = lookup_runtime_artifacts(normalized_chain, target_address, block)
            runtime_summary = {
                "ok": bool(runtime_artifacts),
                "chain": normalized_chain,
                "address": target_address,
                "block": block if block is not None else "latest",
            }
            if runtime_artifacts:
                runtime_dir = target_dir / "runtime_artifacts"
                runtime_dir.mkdir(parents=True, exist_ok=True)
                saved_runtime: dict[str, str] = {}
                for filename, content in runtime_artifacts.items():
                    out_path = runtime_dir / filename
                    out_path.write_text(
                        content if content.endswith("\n") else content + "\n", encoding="utf-8"
                    )
                    saved_runtime[filename] = str(out_path)
                runtime_summary["paths"] = saved_runtime
            on_chain["runtime_artifacts"] = runtime_summary

            recent_txs = lookup_address_transactions(
                normalized_chain,
                target_address,
                offset=self.max_transactions,
                sort="desc",
            )
            on_chain["recent_transactions"] = recent_txs
            tx_items = recent_txs.get("transactions", []) if isinstance(recent_txs, dict) else []
            if isinstance(tx_items, list):
                for item in tx_items:
                    tx_hash = str(item.get("hash", "")).strip()
                    if tx_hash:
                        combined_txs.append(tx_hash)

            traces = lookup_address_transaction_traces(
                normalized_chain,
                target_address,
                offset=min(self.max_transactions, 5),
                sort="desc",
            )
            on_chain["recent_transaction_traces"] = traces
            _write_json(target_dir / "recent_transactions.json", recent_txs)
            _write_json(target_dir / "recent_transaction_traces.json", traces)

        combined_txs = _dedupe_keep_order(combined_txs)[: self.max_transactions]
        tx_reports: list[dict[str, Any]] = []
        tx_dir = target_dir / "transactions"
        for index, tx_hash in enumerate(combined_txs, 1):
            tx_payload = lookup_transaction(normalized_chain, tx_hash) if normalized_chain else {}
            receipt_payload = (
                lookup_transaction_receipt(normalized_chain, tx_hash) if normalized_chain else {}
            )
            tx_path = tx_dir / f"{index:02d}_{tx_hash}_tx.json"
            receipt_path = tx_dir / f"{index:02d}_{tx_hash}_receipt.json"
            _write_json(tx_path, tx_payload)
            _write_json(receipt_path, receipt_payload)
            tx_reports.append(
                {
                    "tx_hash": tx_hash,
                    "transaction_path": str(tx_path),
                    "receipt_path": str(receipt_path),
                    "transaction_ok": bool(tx_payload),
                    "receipt_ok": bool(receipt_payload),
                }
            )

        ranked_report_links = _top_scored(
            [
                {
                    "url": str(item.get("url", "")).strip(),
                    "label": str(item.get("label", "")).strip(),
                    "score": _score_report_link(
                        str(item.get("url", "")).strip(),
                        text=" ".join(
                            part
                            for part in [
                                str(item.get("label", "")).strip(),
                                str(item.get("context", "")).strip(),
                            ]
                            if part
                        ),
                        source_kind=str(item.get("source_kind", "")).strip(),
                    ),
                    "source_kind": str(item.get("source_kind", "")).strip(),
                    "source_tag": str(item.get("source_tag", "")).strip(),
                }
                for item in link_candidates
                if _is_http_url(str(item.get("url", "")).strip())
                and not _is_explorer_url(str(item.get("url", "")).strip())
                and not _is_debug_url(str(item.get("url", "")).strip())
                and _score_report_link(
                    str(item.get("url", "")).strip(),
                    text=" ".join(
                        part
                        for part in [
                            str(item.get("label", "")).strip(),
                            str(item.get("context", "")).strip(),
                        ]
                        if part
                    ),
                    source_kind=str(item.get("source_kind", "")).strip(),
                )
                >= 6
            ],
            value_key="url",
            limit=8,
        )
        ranked_attack_tx_candidates = _top_scored(
            attack_tx_candidates, value_key="tx_hash", limit=8
        )
        ranked_attack_txs = [
            item for item in ranked_attack_tx_candidates if int(item.get("score", 0)) >= 6
        ]
        ranked_addresses = [
            item
            for item in _top_scored(address_candidates, value_key="address", limit=8)
            if int(item.get("score", 0)) >= 4
        ]
        explorer_urls = _dedupe_keep_order(
            str(item.get("url", "")).strip()
            for item in link_candidates
            if _is_explorer_url(str(item.get("url", "")).strip())
        )[:20]
        debug_urls = _dedupe_keep_order(
            str(item.get("url", "")).strip()
            for item in link_candidates
            if _is_debug_url(str(item.get("url", "")).strip())
        )[:20]
        key_findings = {
            "case_link": (
                requested_urls[0]
                if requested_urls
                else (
                    ranked_report_links[0]["url"]
                    if ranked_report_links
                    else (combined_urls[0] if combined_urls else "")
                )
            ),
            "report_links": ranked_report_links,
            "attack_txs": [
                item["tx_hash"] for item in (ranked_attack_txs or ranked_attack_tx_candidates[:3])
            ],
            "attack_tx_confidence": (
                "high" if ranked_attack_txs else ("low" if ranked_attack_tx_candidates else "none")
            ),
            "attack_tx_candidates": ranked_attack_tx_candidates,
            "explorer_urls": explorer_urls,
            "debug_urls": debug_urls,
            "important_addresses": ranked_addresses,
        }

        agent_notes: list[str] = []
        if requested_queries:
            result_count = sum(
                len(item.get("results", [])) for item in search_reports if isinstance(item, dict)
            )
            agent_notes.append(
                f"expanded {len(requested_queries)} query inputs into {result_count} search results and {len(combined_urls)} fetched urls"
            )
        else:
            agent_notes.append(
                f"processed {len(combined_urls)} input urls without search expansion"
            )
        if fallback_queries:
            agent_notes.append(
                "ran fallback search queries for missing attack txs: "
                + ", ".join(fallback_queries[:4])
            )
        agent_notes.append(
            f"fetched {len(page_reports)} web pages with {len(page_errors)} fetch errors"
        )
        if normalized_chain and target_address:
            agent_notes.append(
                f"collected on-chain evidence for {normalized_chain}:{target_address}"
            )
        elif normalized_chain:
            agent_notes.append(
                f"skipped on-chain address lookups because no target address was discovered for chain={normalized_chain}"
            )
        else:
            agent_notes.append("skipped on-chain evidence collection because no chain was provided")

        report = {
            "task": "live_scrape",
            "case_id": case_id,
            "source": "live_web",
            "agent": {
                "name": "live_scrape_agent",
                "strategy": [
                    "web_search_query_expansion",
                    "url_fetch",
                    "html_to_text_normalization",
                    "regex_extract_tx_hashes_and_addresses",
                    "explorer_and_rpc_metadata_lookups",
                ],
            },
            "case_path": "",
            "manual_case_path": "",
            "changed_fields": {},
            "evidence": {
                "inputs": {
                    "chain": normalized_chain,
                    "address": requested_address,
                    "tx_hashes": requested_txs,
                    "urls": requested_urls,
                    "queries": requested_queries,
                    "search_domains": normalized_domains,
                    "search_limit": normalized_search_limit,
                    "block": block,
                },
                "search": {
                    "provider": _DEFAULT_SEARCH_PROVIDER,
                    "queries": search_reports,
                    "errors": search_errors,
                },
                "discovered": {
                    "target_address": target_address,
                    "addresses": combined_addresses[:20],
                    "tx_hashes": combined_txs,
                    "urls": combined_urls,
                },
                "web": {
                    "pages": page_reports,
                    "errors": page_errors,
                },
                "on_chain": on_chain,
                "transactions": tx_reports,
                "key_findings": key_findings,
                "artifacts": {
                    "output_dir": str(target_dir),
                },
            },
            "agent_notes": agent_notes,
            "remaining_annotation_hints": {},
            "source_manual_case": {},
            "suggested_review_case": {},
            "suggested_manual_case": {},
        }
        return report

    def run_session(
        self,
        *,
        chain: str = "",
        address: str = "",
        tx_hashes: Iterable[str] = (),
        urls: Iterable[str] = (),
        queries: Iterable[str] = (),
        search_domains: Iterable[str] = (),
        search_limit: int = _DEFAULT_SEARCH_RESULT_LIMIT,
        block: int | None = None,
        output_dir: Path | None = None,
        poll_interval_seconds: float = 60.0,
        duration_seconds: float | None = None,
        max_iterations: int = 0,
        write_prompt_bundle: bool = False,
        latest_prompt_path: Path | None = None,
        session_manifest_path: Path | None = None,
    ) -> dict[str, Any]:
        session_dir = (
            output_dir.resolve()
            if output_dir is not None
            else self.default_session_dir(chain=chain, address=address)
        )
        session_dir.mkdir(parents=True, exist_ok=True)
        iterations_dir = session_dir / "iterations"
        iterations_dir.mkdir(parents=True, exist_ok=True)

        normalized_duration = (
            None
            if duration_seconds is None or float(duration_seconds) <= 0
            else float(duration_seconds)
        )
        normalized_max_iterations = max(int(max_iterations), 0)
        normalized_interval = max(float(poll_interval_seconds), 0.0)

        manifest_path = (
            session_manifest_path.resolve()
            if session_manifest_path is not None
            else session_dir / "session.json"
        )
        latest_report_path = session_dir / "latest_report.json"
        latest_prompt_root = (
            latest_prompt_path.resolve()
            if latest_prompt_path is not None
            else session_dir / "latest_prompt.txt"
        )
        started_at = _utc_now_iso()
        manifest: dict[str, Any] = {
            "task": "live_scrape",
            "session_id": session_dir.name,
            "source": "live_web",
            "agent": {
                "name": "live_scrape_agent",
                "mode": "continuous",
            },
            "session_dir": str(session_dir),
            "poll_interval_seconds": normalized_interval,
            "duration_seconds": normalized_duration,
            "max_iterations": normalized_max_iterations or None,
            "started_at": started_at,
            "finished_at": "",
            "status": "running",
            "latest_report_path": "",
            "latest_prompt_path": "",
            "iterations": [],
        }
        _write_json(manifest_path, manifest)

        start_monotonic = time.monotonic()
        iteration_index = 0
        status = "completed"

        try:
            while True:
                if normalized_max_iterations and iteration_index >= normalized_max_iterations:
                    break
                if (
                    normalized_duration is not None
                    and iteration_index > 0
                    and (time.monotonic() - start_monotonic) >= normalized_duration
                ):
                    break

                iteration_index += 1
                iteration_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                iteration_dir = iterations_dir / f"{iteration_index:04d}_{iteration_stamp}"
                iteration_started_at = _utc_now_iso()
                report = self.build_report(
                    chain=chain,
                    address=address,
                    tx_hashes=tx_hashes,
                    urls=urls,
                    queries=queries,
                    search_domains=search_domains,
                    search_limit=search_limit,
                    block=block,
                    output_dir=iteration_dir,
                )

                report_path = iteration_dir / "report.json"
                _write_json(report_path, report)
                _write_json(latest_report_path, report)

                prompt_path_text = ""
                if write_prompt_bundle:
                    prompt_bundle = self.build_prompt_bundle(
                        chain=chain,
                        address=address,
                        tx_hashes=tx_hashes,
                        urls=urls,
                        queries=queries,
                        search_domains=search_domains,
                        search_limit=search_limit,
                        block=block,
                        report=report,
                    )
                    prompt_path = iteration_dir / "prompt.txt"
                    prompt_path.write_text(prompt_bundle["combined_prompt"], encoding="utf-8")
                    latest_prompt_root.parent.mkdir(parents=True, exist_ok=True)
                    latest_prompt_root.write_text(
                        prompt_bundle["combined_prompt"], encoding="utf-8"
                    )
                    prompt_path_text = str(prompt_path)
                    manifest["latest_prompt_path"] = str(latest_prompt_root)

                stats = _report_stats(report)
                manifest["latest_report_path"] = str(latest_report_path)
                manifest["iterations"].append(
                    {
                        "iteration": iteration_index,
                        "started_at": iteration_started_at,
                        "finished_at": _utc_now_iso(),
                        "output_dir": str(iteration_dir),
                        "report_path": str(report_path),
                        "prompt_path": prompt_path_text,
                        "case_id": stats["case_id"],
                        "target_address": stats["target_address"],
                        "search_queries": stats["search_queries"],
                        "pages": stats["pages"],
                        "txs": stats["txs"],
                    }
                )
                _write_json(manifest_path, manifest)

                if normalized_max_iterations and iteration_index >= normalized_max_iterations:
                    break
                if (
                    normalized_duration is not None
                    and (time.monotonic() - start_monotonic) >= normalized_duration
                ):
                    break
                if normalized_interval > 0:
                    time.sleep(normalized_interval)
        except KeyboardInterrupt:
            status = "interrupted"

        manifest["status"] = status
        manifest["finished_at"] = _utc_now_iso()
        _write_json(manifest_path, manifest)
        return manifest

    def build_prompt_bundle(
        self,
        *,
        chain: str = "",
        address: str = "",
        tx_hashes: Iterable[str] = (),
        urls: Iterable[str] = (),
        queries: Iterable[str] = (),
        search_domains: Iterable[str] = (),
        search_limit: int = _DEFAULT_SEARCH_RESULT_LIMIT,
        block: int | None = None,
        report: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        normalized_inputs = {
            "chain": str(chain).strip(),
            "address": str(address).strip(),
            "tx_hashes": _dedupe_keep_order(tx_hashes),
            "urls": _dedupe_keep_order(urls),
            "queries": _dedupe_keep_order(queries),
            "search_domains": _dedupe_keep_order(search_domains),
            "search_limit": max(int(search_limit), 1),
            "block": block,
        }
        current_report = (
            report
            if report is not None
            else self.build_report(
                chain=chain,
                address=address,
                tx_hashes=tx_hashes,
                urls=urls,
                queries=queries,
                search_domains=search_domains,
                search_limit=search_limit,
                block=block,
            )
        )
        evidence = current_report.get("evidence", {}) if isinstance(current_report, dict) else {}
        discovered = evidence.get("discovered", {}) if isinstance(evidence, dict) else {}
        search = evidence.get("search", {}) if isinstance(evidence, dict) else {}
        web = evidence.get("web", {}) if isinstance(evidence, dict) else {}
        on_chain = evidence.get("on_chain", {}) if isinstance(evidence, dict) else {}
        txs = evidence.get("transactions", []) if isinstance(evidence, dict) else []
        key_findings = evidence.get("key_findings", {}) if isinstance(evidence, dict) else {}
        artifacts = evidence.get("artifacts", {}) if isinstance(evidence, dict) else {}
        output_dir = str(artifacts.get("output_dir", "")).strip() or "(not provided)"
        user_prompt = LIVE_SCRAPE_AGENT_PROMPT.format(
            inputs=json.dumps(normalized_inputs, indent=2, ensure_ascii=False, sort_keys=True),
            search=json.dumps(search, indent=2, ensure_ascii=False, sort_keys=True),
            discovered=json.dumps(discovered, indent=2, ensure_ascii=False, sort_keys=True),
            web=json.dumps(web, indent=2, ensure_ascii=False, sort_keys=True),
            on_chain=json.dumps(on_chain, indent=2, ensure_ascii=False, sort_keys=True),
            txs=json.dumps(txs, indent=2, ensure_ascii=False, sort_keys=True),
            key_findings=json.dumps(key_findings, indent=2, ensure_ascii=False, sort_keys=True),
            output_dir=output_dir,
            output_schema=LIVE_SCRAPE_OUTPUT_SCHEMA.strip(),
        )
        system_prompt = ""
        combined_prompt = f"{user_prompt.strip()}\n"
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "combined_prompt": combined_prompt,
        }
