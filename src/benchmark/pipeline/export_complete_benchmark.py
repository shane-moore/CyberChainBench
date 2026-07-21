from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from eth_utils import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Cases where attacker_profit is unreliable (0 or near-0) due to known
# limitations of the profit calculation tool.  Their attacker_profit is
# forced to None during export so downstream consumers don't treat them
# as zero-profit attacks.
#
# Root causes:
#   no_quote     – attacker received tokens but no DEX liquidity to price them
#                  (protocol-specific tokens, LP/BPT, Pendle PT, etc.)
#   no_flows     – attack tx has no standard ERC20 Transfer events
#                  (governance attacks, multisig exploits, cross-chain bridges)
#   nft          – profit is in ERC721/ERC1155 transfers (not parsed)
#   wrong_tx     – recorded attack_tx is not the main profit-taking transaction
#   overflow     – token amount is corrupted / uint128-max overflow
#   negative     – net profit is negative due to mispriced outflows
_UNRELIABLE_PROFIT_CASE_IDS: set[str] = {
    # no_quote: token unquotable via Uniswap/PancakeSwap routers
    "dfhl-0001",   # Visor Finance – VVISR token
    "dfhl-0012",   # DAO Maker – SHD token
    "dfhl-0045",   # Bancor Protocol
    "dfhl-0102",   # Templedao
    "dfhl-0159",   # Creat Future – CF token
    "dfhl-0193",   # PHIL
    "dfhl-0406",   # Matez
    "dfhl-0459",   # Spectra_finance
    "dfhl-0498",   # TSURU
    "dfhl-0545",   # Seneca – PT-RSETH (Pendle)
    "dfhl-0546",   # SMOOFSStaking
    "dfhl-0586",   # BalancerV2 – BPT tokens
    "dfhl-0601",   # SizeCredit
    "dfhl-0690",   # PRXVT
    # no_flows: no ERC20 Transfer events in the attack tx
    "dfhl-0034",   # bzx – internal protocol state change
    "dfhl-0143",   # GYMNetwork
    "dfhl-0144",   # Optimism – cross-chain airdrop exploit
    "dfhl-0175",   # BuildFinance – governance attack
    "dfhl-0179",   # Qubit Finance – cross-chain bridge
    "dfhl-0189",   # FloorProtocol
    "dfhl-0334",   # landNFT
    "dfhl-0434",   # Unverified_766a
    "dfhl-0535",   # MO
    "dfhl-0540",   # UnizenIO
    "dfhl-0554",   # RuggedArt
    "dfhl-0555",   # ParticleTrade
    "dfhl-0576",   # WiseLending
    "dfhl-0578",   # LQDX
    "dfhl-0603",   # coinbase
    "dfhl-0660",   # Bybit – Safe multisig exploit
    # nft: ERC721/ERC1155 transfers not parsed
    "dfhl-0121",   # Bad Guys by RPF
    "dfhl-0137",   # FlippazOne NFT
    "dfhl-0174",   # TreasureDAO
    "dfhl-0176",   # Sandbox LAND
    # wrong_tx: attack_tx is not the main profit tx
    "dfhl-0018",   # Levyathan Finance – emergencyWithdraw tx, not the mint+sell
    "dfhl-0177",   # Meter – main exploit on Meter chain, not BSC
    "dfhl-0064",   # NOVAToken
    # overflow: token amount corrupted
    "dfhl-0433",   # Shezmu – WBTC amount = 2^128
    # negative / near-zero net
    "dfhl-0376",   # Sheep – negative profit from mispriced outflows
    "dfhl-0380",   # Spherax USDs
    "dfhl-0076",   # Polynomial
    "dfhl-0208",   # FiberRouter
    "dfhl-0215",   # EHX
    # rpc_fail: RPC cannot fetch historical receipt for these chains
    "dfhl-0011",   # ZABU Finance (avalanche)
    "dfhl-0058",   # ElasticSwap (avalanche)
    "dfhl-0592",   # Kame (sei)
    "dfhl-0656",   # Venus_ZKSync (zksync)
    "dfhl-0483",   # VeloCore (linea)
    "dfhl-0462",   # Minterest (mantle)
    # no_quote: token unquotable on these chains
    "dfhl-0205",   # CAROLProtocol (base)
    "dfhl-0276",   # LeetSwap (base)
    # no_attacker: old ethereum txs where skip rules exclude all candidates
    "dfhl-0035",   # SmartMesh
    "dfhl-0046",   # LendfMe
    "dfhl-0047",   # UniSwapV1
    "dfhl-0048",   # SpankChain
    "dfhl-0049",   # Beauty Chain
}


def _extract_selectors_from_bytecode(bytecode: str) -> set[str]:
    """Extract all 4-byte PUSH4 selectors from EVM bytecode."""
    code = bytecode.strip()
    if code.startswith("0x"):
        code = code[2:]
    selectors: set[str] = set()
    i = 0
    while i < len(code) - 9:
        opcode = int(code[i:i + 2], 16) if code[i:i + 2] else 0
        if opcode == 0x63:  # PUSH4
            sel = "0x" + code[i + 2:i + 10]
            if len(sel) == 10:
                selectors.add(sel.lower())
            i += 10
        elif 0x60 <= opcode <= 0x7F:  # PUSH1..PUSH32
            push_bytes = opcode - 0x5F
            i += 2 + push_bytes * 2
        else:
            i += 2
    return selectors


def _try_compute_selector(func_name: str, on_chain_selectors: set[str] | None = None) -> str | None:
    """Compute 4-byte selector from a human-readable function name.

    When *on_chain_selectors* is provided, only return a selector that exists
    in the contract bytecode.
    """
    name = func_name.strip()
    if not name:
        return None
    if "(" in name:
        candidates = [name]
    else:
        candidates = [
            f"{name}()",
            f"{name}(uint256)",
            f"{name}(address)",
            f"{name}(address,uint256)",
            f"{name}(uint256,address)",
            f"{name}(bytes)",
            f"{name}(bytes,bytes,uint64)",
            f"{name}(uint256,uint256)",
            f"{name}(address,address)",
            f"{name}(address,address,uint256)",
            f"{name}(address,uint256,uint256)",
            f"{name}(uint256,address,uint256)",
            f"{name}(bool)",
            f"{name}(uint256,bytes)",
            f"{name}(address,bytes)",
            f"{name}(address,address,uint256,uint256)",
            f"{name}(address,uint256,uint256,uint256)",
            f"{name}(uint256,uint256,uint256)",
            f"{name}(address[],uint256[],uint256[],bytes)",
            f"{name}(address,uint256,uint256,bytes)",
            f"{name}(address,address,uint256,bytes)",
        ]
    cast_bin = shutil.which("cast")
    for sig in candidates:
        sel: str | None = None
        if cast_bin:
            try:
                proc = subprocess.run(
                    [cast_bin, "sig", sig],
                    capture_output=True, text=True, timeout=5,
                )
                if proc.returncode == 0:
                    raw = proc.stdout.strip()
                    if raw.startswith("0x") and len(raw) == 10:
                        sel = raw.lower()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if sel is None:
            try:
                sel_bytes = keccak(text=sig)[:4]
                sel = "0x" + sel_bytes.hex()
            except Exception:
                continue
        if on_chain_selectors is not None:
            if sel in on_chain_selectors:
                return sel
        else:
            return sel
    return None


def _fetch_on_chain_selectors(chain: str, addresses: list[str], block: object) -> set[str] | None:
    """Fetch runtime bytecode from one or more addresses and extract PUSH4 selectors."""
    try:
        from infra.chain.metadata import lookup_runtime_code
    except Exception:
        return None
    combined: set[str] | None = None
    for addr in addresses:
        if not addr:
            continue
        try:
            bytecode = lookup_runtime_code(chain, addr, block)
            if bytecode:
                sels = _extract_selectors_from_bytecode(bytecode)
                if combined is None:
                    combined = sels
                else:
                    combined |= sels
        except Exception:
            pass
    return combined


def _is_missing(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set)):
        return len(value) == 0
    return False


def _complete_except_file(case: dict) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for key in [
        "case_link",
        "attack_txs",
        "chain",
        "block_number",
        "vulnerable_address",
        "has_public_source",
        "fixable",
        "function",
        "type",
    ]:
        if key == "function" and not case.get("has_public_source"):
            continue
        if _is_missing(case.get(key)):
            missing.append(key)
    if case.get("fixable") is True and _is_missing(case.get("proxy_address")):
        missing.append("proxy_address")
    return (not missing), missing


def _load_cases(source_root: Path) -> list[dict]:
    """Load cases from either curator output or legacy layout.

    Fill-agent output:  <source_root>/cases/<source>/*.json
    Legacy layout:      <source_root>/benchmark_case/<source>/*.json
    """
    cases_dir = source_root / "cases"
    if not cases_dir.exists():
        cases_dir = source_root / "benchmark_case"
    if not cases_dir.exists():
        raise FileNotFoundError(
            f"No cases/ or benchmark_case/ directory found under {source_root}"
        )

    items: list[dict] = []
    for path in sorted(cases_dir.rglob("*.json")):
        if path.name == "cases.json":
            continue
        payload = json.loads(path.read_text())
        if isinstance(payload, dict):
            items.append(payload)
    return items


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Export complete benchmark subset (all fields complete except file)."
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("data/benchmark/drafts/benchmark_case_20260412_040508"),
    )
    parser.add_argument(
        "--output-root", type=Path, default=Path("data/benchmark/cases")
    )
    parser.add_argument(
        "--single-tx",
        action="store_true",
        help="Only include cases with exactly one attack transaction.",
    )
    args = parser.parse_args()

    source_root = args.source_root
    output_root = args.output_root

    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    selected: list[dict] = []
    skipped: list[tuple[str, list[str]]] = []
    running = 1
    for payload in _load_cases(source_root):
        ok, missing = _complete_except_file(payload)
        if not ok:
            case_id = str(payload.get("id", "")).strip()
            skipped.append((case_id, missing))
            continue
        if args.single_tx:
            txs = payload.get("attack_txs") or []
            if len(txs) != 1:
                case_id = str(payload.get("id", "")).strip()
                skipped.append((case_id, [f"multi_tx({len(txs)})"]))
                continue
        case_id = str(payload.get("id", "")).strip()
        if not case_id:
            continue
        new_id = f"bench-{running:02d}"
        running += 1
        rewritten = dict(payload)
        rewritten["source_case_id"] = case_id
        rewritten["id"] = new_id
        if case_id in _UNRELIABLE_PROFIT_CASE_IDS:
            rewritten["attacker_profit"] = None
        if rewritten.get("has_public_source") and rewritten.get("function"):
            func = str(rewritten["function"]).strip()
            if func.startswith("0x") and len(func) == 10:
                print(f"  WARNING: {new_id} has_public_source=true but function is selector {func}")
        if not rewritten.get("has_public_source") and rewritten.get("function"):
            func = str(rewritten["function"]).strip()
            if not func.startswith("0x"):
                chain = str(rewritten.get("chain") or "").strip()
                address = str(rewritten.get("vulnerable_address") or "").strip()
                proxy = str(rewritten.get("proxy_address") or "").strip()
                block = rewritten.get("block_number")
                addrs = [a for a in (address, proxy) if a]
                on_chain = _fetch_on_chain_selectors(chain, addrs, block) if chain and addrs else None
                selector = _try_compute_selector(func, on_chain)
                if selector:
                    rewritten["function"] = selector
                else:
                    rewritten["function"] = None
        (output_root / f"{new_id}.json").write_text(
            json.dumps(rewritten, indent=2, ensure_ascii=False) + "\n"
        )
        selected.append(rewritten)

    print(
        json.dumps(
            {
                "source_root": str(source_root),
                "output_root": str(output_root),
                "total_loaded": len(selected) + len(skipped),
                "selected_count": len(selected),
                "skipped_count": len(skipped),
                "first_ids": [case["id"] for case in selected[:10]],
            },
            indent=2,
        )
    )
    if skipped:
        print(f"\nSkipped {len(skipped)} incomplete cases (first 10):")
        for case_id, missing in skipped[:10]:
            print(f"  {case_id}: missing {missing}")


if __name__ == "__main__":
    main()
