"""
Extract minimal DeFiHackLabs case-link records from README headings.

This parser is intentionally link-focused:
- source of truth is the README heading anchor
- exploit path is recovered only from the README section
- no chain/category/address/source parsing is done here
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from project_layout import DEFIHACKLABS_DIR, PARSER_PREPROCESSED_DIR

_DFHL_REPO_BLOB_ROOT = "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main"


def _github_blob_url(repo_root: Path, file_path: Path) -> str:
    relative = file_path.relative_to(repo_root).as_posix()
    return f"{_DFHL_REPO_BLOB_ROOT}/{relative}"


def _github_heading_anchor(heading_text: str) -> str:
    slug = heading_text.strip().lower()
    slug = re.sub(r"[^\w\- ]", "", slug)
    return slug.replace(" ", "-")


def _normalize_sol_relative(readme_path: Path, repo_root: Path, raw_path: str) -> str:
    candidate = raw_path.strip().strip("`").strip()
    if not candidate:
        return ""
    if candidate.startswith("./src/") or candidate.startswith("src/"):
        return candidate[2:] if candidate.startswith("./") else candidate
    try:
        resolved = (readme_path.parent / candidate).resolve()
        return resolved.relative_to(repo_root.resolve()).as_posix()
    except Exception:
        candidate = re.sub(r"^(?:\.\./)+", "", candidate)
        return candidate[2:] if candidate.startswith("./") else candidate


def _extract_contract_sol_relative(
    section: str, readme_path: Path, repo_root: Path, date_str: str
) -> str:
    contract_block = re.search(
        r"(?:^|\n)(?:#+\s*)?Contract\s*\n+(.*?)(?=\n\s*(?:#+\s*)?(?:Link reference|References?)\b|\Z)",
        section,
        re.IGNORECASE | re.DOTALL,
    )
    block = contract_block.group(1) if contract_block else section

    link_match = re.search(r"\[[^\]]+\.sol\]\(([^)]+\.sol)\)", block, re.IGNORECASE)
    if link_match:
        return _normalize_sol_relative(readme_path, repo_root, link_match.group(1))

    filename_match = re.search(r"^\s*([A-Za-z0-9_.-]+\.sol)\s*$", block, re.MULTILINE)
    if filename_match:
        month_dir = f"{date_str[:4]}-{date_str[4:6]}"
        return f"src/test/{month_dir}/{filename_match.group(1)}"
    return ""


def parse_readme_entries(readme_path: Path, repo_root: Path) -> list[dict]:
    """Parse README headings into minimal link-oriented entries."""
    content = readme_path.read_text(errors="replace")
    readme_url = _github_blob_url(repo_root, readme_path)
    entries: list[dict] = []

    heading_pattern = re.compile(r"^### (\d{8})\s+-\s+(.+?)\s*$", re.MULTILINE)
    matches = list(heading_pattern.finditer(content))
    for i, match in enumerate(matches):
        date_str = match.group(1)
        title = match.group(2)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        section = content[start:end]

        if " - " in title:
            name = title.split(" - ", 1)[0].strip()
        elif "---" in title:
            name = title.split("---", 1)[0].strip()
        else:
            name = title.strip()

        forge_cmd = ""
        sol_relative = ""
        forge_line_match = re.search(r"^\s*(forge test\s+.+?)\s*$", section, re.MULTILINE)
        if forge_line_match:
            forge_cmd = forge_line_match.group(1).strip()
            contracts_match = re.search(r"--contracts\s+(\S+)", forge_cmd)
            if contracts_match:
                sol_relative = _normalize_sol_relative(
                    readme_path, repo_root, contracts_match.group(1)
                )
        if not sol_relative:
            sol_relative = _extract_contract_sol_relative(section, readme_path, repo_root, date_str)

        heading_anchor = _github_heading_anchor(f"{date_str} {title}")
        entries.append(
            {
                "date_str": date_str,
                "date": f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}",
                "name": name,
                "sol_relative": sol_relative,
                "forge_cmd": forge_cmd,
                "case_link": f"{readme_url}#{heading_anchor}",
            }
        )

    return entries


def _minimal_case_entry(*, case_id: str, name: str, sol_relative: str, case_link: str) -> dict:
    return {
        "id": case_id,
        "name": name,
        "source": "DeFiHackLabs",
        "exploit": f"{(DEFIHACKLABS_DIR / sol_relative).as_posix()}",
        "case_link": case_link,
    }


def _write_output(output_dir: Path, cases: list[dict]) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(cases, indent=2, ensure_ascii=False) + "\n"
    (output_dir / "case_links.json").write_text(payload)


def extract_all(repo_root: Path, output_dir: Path | None = None) -> list[dict]:
    """Extract minimal DeFiHackLabs link records from README files."""
    readme_files = sorted(repo_root.glob("past/*/README.md"))
    main_readme = repo_root / "README.md"
    if main_readme.exists():
        readme_files.append(main_readme)

    all_entries: list[dict] = []
    for readme_path in readme_files:
        all_entries.extend(parse_readme_entries(readme_path, repo_root))

    print(f"[DeFiHackLabs] Parsed {len(all_entries)} entries from README files")

    cases: list[dict] = []
    seen_files: set[str] = set()
    counter = 0
    for entry in all_entries:
        sol_relative = str(entry.get("sol_relative", "")).strip()
        if not sol_relative or sol_relative in seen_files:
            continue
        seen_files.add(sol_relative)
        counter += 1
        cases.append(
            _minimal_case_entry(
                case_id=f"dfhl-{counter:04d}",
                name=str(entry.get("name", "")).strip(),
                sol_relative=sol_relative,
                case_link=str(entry.get("case_link", "")).strip(),
            )
        )

    if output_dir is not None:
        _write_output(output_dir, cases)

    print(f"[DeFiHackLabs] Extracted {len(cases)} cases")
    if output_dir is not None:
        print(f"[DeFiHackLabs] Output: {output_dir}")
    return cases


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract minimal case-link records from DeFiHackLabs"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=DEFIHACKLABS_DIR,
        help="Path to DeFiHackLabs repo",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PARSER_PREPROCESSED_DIR / "defihacklabs",
        help="Output directory for extracted case-link records",
    )
    args = parser.parse_args()

    extract_all(args.repo, args.output)


if __name__ == "__main__":
    main()
