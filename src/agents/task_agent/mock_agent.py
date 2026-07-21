"""
Mock agent for pipeline testing.

Uses reference exploit from the dataset as the "agent's response",
so we can validate the full detect → exploit → fix pipeline
without calling any real LLM API.
"""

from __future__ import annotations

from pathlib import Path

from .base import AgentResponse, BaseAgent, TaskType


class MockAgent(BaseAgent):
    """Mock agent that returns reference data from the dataset."""

    def __init__(self, model: str = "mock-reference", base_dir: Path | None = None, **kwargs):
        super().__init__(model, **kwargs)
        self.base_dir = base_dir or Path(".")

    def detect(
        self,
        contract_code: dict[str, str],
        context: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Return a detection based on context (which contains ground truth description)."""
        # Simulate: agent identifies the vulnerability from the code
        return AgentResponse(
            task_type=TaskType.DETECT,
            raw_response=f"Vulnerability detected: {context}\n\n"
            "Type: reentrancy\n"
            "Location: The contract contains a function that makes external calls "
            "before updating state, allowing re-entrancy attacks.\n"
            "Severity: critical\n"
            "Recommendation: Add reentrancy guard or follow checks-effects-interactions pattern.",
            workspace_dir=workspace_dir or None,
            vulnerability_type="reentrancy",
            vulnerability_description=context,
        )

    def exploit(
        self,
        contract_code: dict[str, str],
        vulnerability_hint: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Return the reference exploit from the dataset (if available in contract_code)."""
        # For DeFiHackLabs cases, the "vulnerable" code IS the exploit code
        # So we just return it as the agent's exploit output
        code = next(iter(contract_code.values()), None) or """
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function testExploit() public {
        revert("mock exploit input is metadata-only");
    }
}
""".strip()
        return AgentResponse(
            task_type=TaskType.EXPLOIT,
            raw_response="Here is the exploit PoC:",
            workspace_dir=workspace_dir or None,
            exploit_code=code,
        )

    def fix(
        self,
        contract_code: dict[str, str],
        vulnerability_description: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Return a simple fix (add nonReentrant modifier stub)."""
        first_item = next(iter(contract_code.items()), ("", ""))
        path, code = first_item
        # Simple mock fix: just return the original code
        # (this should make the exploit still pass → fix score = 0)
        return AgentResponse(
            task_type=TaskType.PATCH,
            raw_response="Patch: add nonReentrant modifier",
            workspace_dir=workspace_dir or None,
            fixed_code=code,
            file_patches={path: code} if path and code else {},
            fix_possible=True,
            fix_rationale="Mock agent assumes the benchmark patch lane is available.",
            required_authority="proxy admin",
            fix_target_contracts=[path] if path else [],
            fix_confidence="low",
        )
