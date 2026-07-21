"""
Base class for AI agent adapters.

Each agent adapter wraps an LLM API and provides a unified interface
for the three benchmark tasks: detect, exploit, patch.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class TaskType(str, Enum):
    DETECT = "detect"
    EXPLOIT = "exploit"
    PATCH = "patch"
    FILL = "fill"


@dataclass
class AgentResponse:
    """Standardized response from an agent."""

    task_type: TaskType
    raw_response: str
    workspace_dir: str | None = None
    session_log_path: str | None = None
    session_log_text: str | None = None
    agent_elapsed_seconds: float | None = None
    input_tokens_total: int | None = None
    output_tokens_total: int | None = None
    cache_read_input_tokens_total: int | None = None
    cache_write_input_tokens_total: int | None = None
    # Detection fields
    vulnerability_type: str | None = None
    vulnerability_location: str | None = None
    vulnerability_description: str | None = None
    # Exploit fields
    exploit_code: str | None = None
    exploit_execution_project: str | None = None
    exploit_source_path: str | None = None
    # Patch fields
    fixed_code: str | None = None
    file_patches: dict[str, str] | None = None
    fix_description: str | None = None
    fix_possible: bool | None = None
    fix_rationale: str | None = None
    required_authority: str | None = None
    fix_target_contracts: list[str] = field(default_factory=list)
    fix_confidence: str | None = None

    @property
    def has_code(self) -> bool:
        return bool(self.exploit_code or self.fixed_code or self.file_patches)


class BaseAgent(ABC):
    """Abstract base for agent adapters."""

    supports_tools = False

    def __init__(self, model: str, **kwargs):
        self.model = model
        self.config = kwargs

    @abstractmethod
    def detect(
        self,
        contract_code: dict[str, str],
        context: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Ask the agent to find vulnerabilities in the contract code.

        Args:
            contract_code: {filename: source_code} mapping
            context: Optional additional context about the protocol
            case_id: Benchmark case id used for per-case evaluation workspaces
            workspace_dir: Optional pre-created evaluation workspace path
        """
        ...

    @abstractmethod
    def exploit(
        self,
        contract_code: dict[str, str],
        vulnerability_hint: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Ask the agent to write a PoC exploit.

        Args:
            contract_code: {filename: source_code} mapping
            vulnerability_hint: Optional hint about the vulnerability
            case_id: Benchmark case id used only for local validation infra
            workspace_dir: Optional pre-created evaluation workspace path
        """
        ...

    @abstractmethod
    def fix(
        self,
        contract_code: dict[str, str],
        vulnerability_description: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        """Ask the agent to fix the vulnerability.

        Args:
            contract_code: {filename: source_code} mapping
            vulnerability_description: Description of the vulnerability to fix
            case_id: Benchmark case id used for per-case evaluation workspaces
            workspace_dir: Optional pre-created evaluation workspace path
        """
        ...

    def _format_contracts(self, contract_code: dict[str, str]) -> str:
        """Format contract code into a prompt-friendly string."""
        parts = []
        for filename, code in contract_code.items():
            parts.append(f"// === {filename} ===\n{code}")
        if not parts:
            return "(no local source files provided)"
        return "\n\n".join(parts)
