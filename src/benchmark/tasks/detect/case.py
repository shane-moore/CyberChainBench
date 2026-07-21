"""Detect benchmark case type."""

from __future__ import annotations

from dataclasses import dataclass, field

from benchmark.base import _CaseBase


@dataclass
class DetectCase(_CaseBase):
    """A single detect benchmark case.

    ground_truth: { type, file?, function?, line? }
    """

    ground_truth: dict = field(default_factory=dict)
    acceptable_alternatives: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> DetectCase:
        chain_context = dict(data.get("chain_context", {}) or {})
        ground_truth = dict(data.get("ground_truth", {}) or {})
        location = ground_truth.get("location")
        if isinstance(location, dict):
            for key in ("file", "contract", "function", "line", "line_range"):
                if key not in ground_truth and key in location:
                    ground_truth[key] = location[key]

        # New flat benchmark_case schema support.
        flat_type = str(data.get("type", "")).strip()
        flat_file = str(data.get("file", "")).strip()
        flat_function = str(data.get("function", "")).strip()
        flat_vulnerable = str(data.get("vulnerable_address", "")).strip()
        flat_attack_txs = data.get("attack_txs", []) if isinstance(data.get("attack_txs", []), list) else []
        flat_proxy = str(data.get("proxy_address", "")).strip()
        flat_block_raw = data.get("block_number") if data.get("block_number") not in (None, "") else data.get("block")
        try:
            flat_block_number = int(flat_block_raw) if flat_block_raw not in (None, "") else None
        except (TypeError, ValueError):
            flat_block_number = None

        if flat_type and not str(ground_truth.get("type", "")).strip():
            ground_truth["type"] = flat_type
        if flat_file and not str(ground_truth.get("file", "")).strip():
            ground_truth["file"] = flat_file
        if flat_function and not str(ground_truth.get("function", "")).strip():
            ground_truth["function"] = flat_function
        if flat_vulnerable and not str(ground_truth.get("vulnerable_address", "")).strip():
            ground_truth["vulnerable_address"] = flat_vulnerable

        contracts = dict(data.get("contracts", {}) or {})
        vulnerable_contract = str(
            ground_truth.get("vulnerable_address", "")
            or ground_truth.get("vulnerable_contract", "")
            or flat_vulnerable
        ).strip()
        target_addresses = chain_context.get("target_addresses", []) or chain_context.get(
            "vulnerable_addresses", []
        )
        first_target = vulnerable_contract or (
            str(target_addresses[0]).strip() if target_addresses else ""
        )
        contracts.setdefault("vulnerable", [])
        contracts.setdefault("exploit", str(data.get("exploit", "")).strip())
        if first_target and not str(contracts.get("vulnerable_address", "")).strip():
            contracts["vulnerable_address"] = first_target
        if first_target:
            chain_context.setdefault("vulnerable_addresses", [first_target])
            chain_context.setdefault("target_addresses", [first_target])
        if flat_attack_txs and not chain_context.get("attack_txs"):
            chain_context["attack_txs"] = [str(item).strip() for item in flat_attack_txs if str(item).strip()]
        if flat_proxy and not chain_context.get("proxy_addresses"):
            chain_context["proxy_addresses"] = [flat_proxy]
        if flat_block_number is not None:
            chain_context.setdefault("block", flat_block_number)
            chain_context.setdefault("fork_block", max(flat_block_number - 1, 1))
        if "chain" in chain_context and "fork_chain" not in chain_context:
            chain_context["fork_chain"] = chain_context["chain"]
        alt_raw = data.get("acceptable_alternatives")
        acceptable_alternatives: dict[str, list[str]] = {}
        if isinstance(alt_raw, dict):
            for key in ("function",):
                vals = alt_raw.get(key)
                if isinstance(vals, list):
                    acceptable_alternatives[key] = [str(v).strip() for v in vals if str(v).strip()]

        return cls(
            id=data["id"],
            name=data["name"],
            source=data["source"],
            case_link=data.get("case_link", ""),
            category=data.get("category", "") or flat_type or str(ground_truth.get("type", "")),
            severity=data.get("severity", ""),
            chain=data.get("chain", "")
            or str(chain_context.get("chain", "") or chain_context.get("fork_chain", "")),
            date=data.get("date", ""),
            description=data.get("description", ""),
            contracts=contracts,
            language=data.get("language", ""),
            vm_family=data.get("vm_family", ""),
            cross_chain=bool(data.get("cross_chain", False)),
            chains_involved=data.get("chains_involved", []),
            chain_context=chain_context,
            state_context=data.get("state_context", {}),
            annotation_hints=data.get("annotation_hints", {}) or {},
            ground_truth=ground_truth,
            acceptable_alternatives=acceptable_alternatives,
            raw=data,
        )
