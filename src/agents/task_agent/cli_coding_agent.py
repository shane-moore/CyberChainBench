"""Shared base for external coding-agent CLIs such as Claude Code and Codex."""

from __future__ import annotations

import json
import os
from pathlib import Path

from project_layout import BENCHMARK_CASES_DIR as BENCHMARK_DIR, DEFIHACKLABS_DIR, DETECT_WORKSPACE_DIR, EXPLOIT_WORKSPACE_DIR, PATCH_WORKSPACE_DIR, resolve_repo_path
from project_root import PROJECT_ROOT
from prompts.detect import DETECT_OUTPUT_SCHEMA as DETECT_JSON_SCHEMA
from agents.task_agent.output_parser import (
    extract_code_block,
    extract_fix_plan,
    extract_named_code_blocks,
    extract_vuln_type,
)
from prompts.detect import BENCHMARK_CLI_DETECT_PROMPT as CLI_DETECT_PROMPT
from prompts.curator import render_type_descriptions
from prompts.exploit import BENCHMARK_CLI_EXPLOIT_PROMPT as CLI_EXPLOIT_PROMPT
from prompts.exploit import EXPLOIT_OUTPUT_SCHEMA
from prompts.patch import BENCHMARK_CLI_PATCH_PROMPT as CLI_PATCH_PROMPT, PATCH_OUTPUT_SCHEMA
CLI_FIX_PROMPT = CLI_PATCH_PROMPT
FIX_OUTPUT_SCHEMA = PATCH_OUTPUT_SCHEMA

from .base import AgentResponse, BaseAgent, TaskType
from .cli_execution import run_prompt
from .cli_workspace import (
    load_case_tool_context,
    parse_case_context,
    prepare_workspace,
    render_tool_guide,
    stage_contract_code,
)

CLI_FAMILY_SPECS: dict[str, dict[str, object]] = {
    "claude_code": {
        "default_model": "claude-sonnet-4-5-20250929",
        "default_bin": "claude",
        "bin_env_var": "CLAUDE_CODE_BIN",
        "work_dir_slug": "claudecodeagent",
    },
    "codex_cli": {
        "default_model": "gpt-5.2",
        "default_bin": "codex",
        "bin_env_var": "CODEX_BIN",
        "work_dir_slug": "codexcliagent",
    },
    "gemini_cli": {
        "default_model": "gemini-2.5-pro-preview-06-05",
        "default_bin": "gemini",
        "bin_env_var": "GEMINI_CLI_BIN",
        "work_dir_slug": "geminicliagent",
    },
    "aider": {
        "default_model": "gpt-5.2",
        "default_bin": "aider",
        "bin_env_var": "AIDER_BIN",
        "work_dir_slug": "aideragent",
    },
    "opencode": {
        "default_model": "openai/gpt-5.2",
        "default_bin": "opencode",
        "bin_env_var": "OPENCODE_BIN",
        "work_dir_slug": "opencodeagent",
    },
    "openhands": {
        "default_model": "anthropic/claude-opus-4-5-20251101",
        "default_bin": "/home/user/.pyenv/versions/openhands_env/bin/python",
        "bin_env_var": "OPENHANDS_BIN",
        "work_dir_slug": "openhandsagent",
    },
}

CODEX_WRAPPER = PROJECT_ROOT / "src" / "wrappers" / "codex_exec_online.py"
CLAUDE_WRAPPER = PROJECT_ROOT / "src" / "wrappers" / "claude_exec_online.py"


def _merge_case_prompt_fields(root_dir: Path, benchmark_dir: Path, task_type: TaskType, context_text: str, case_id: str) -> dict[str, object]:
    import re

    info = parse_case_context(context_text)
    hidden = load_case_tool_context(str(root_dir / benchmark_dir), task_type.value, case_id)

    def _pick(*values: object) -> str:
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    addresses: list[str] = []
    for value in list(info.get("vulnerable_addresses", [])) + list(hidden.get("vulnerable_addresses", [])):
        item = str(value).strip()
        if item and item not in addresses:
            addresses.append(item)
    single_contract = _pick(info.get("single_vulnerable_contract"))
    if single_contract and single_contract not in addresses:
        addresses.insert(0, single_contract)

    attack_txs: list[str] = []
    for value in list(info.get("attack_txs", [])) + list(hidden.get("attack_txs", [])):
        item = str(value).strip()
        if item and item not in attack_txs:
            attack_txs.append(item)

    raw = str(context_text or "")

    def _capture(pattern: str) -> str:
        match = re.search(pattern, raw, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _runtime_block(*values: object) -> str:
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            try:
                block = int(text)
            except (TypeError, ValueError):
                continue
            if task_type in (TaskType.EXPLOIT, TaskType.PATCH):
                return str(max(block - 1, 1))
            return str(block)
        return ""

    return {
        "case_id": case_id or "(not provided)",
        "chain": _pick(info.get("chain"), hidden.get("chain"), _capture(r"chain:\s*([^\n]+)")) or "(not provided)",
        "block_number": _runtime_block(
            info.get("block_number"),
            hidden.get("block_number"),
            info.get("block"),
            hidden.get("block"),
            _capture(r"block_number:\s*(\d+)"),
            _capture(r"Fork block:\s*(\d+)"),
        ),
        "target_contract_address": addresses[0] if addresses else "(not provided)",
        "proxy_contract_address": _pick(hidden.get("proxy_address"), "(not provided)") or "(not provided)",
        "vulnerable_address": addresses[0] if addresses else "(not provided)",
        "vulnerable_address_hint": ", ".join(addresses) if addresses else "(not provided)",
        "attack_tx_hashes": ", ".join(attack_txs) if attack_txs else "(none)",
        "type_hint": _pick(
            _capture(r"type:\s*([^\n]+)"),
            _capture(r"ground_truth\.type:\s*([^\n]+)"),
            _capture(r"Vulnerability type:\s*([^\n]+)"),
        ) or "(not provided)",
        "file_hint": _pick(
            _capture(r"file:\s*([^\n]+)"),
            _capture(r"ground_truth\.file:\s*([^\n]+)"),
            _capture(r"Vulnerability file:\s*([^\n]+)"),
        ) or "(not provided)",
        "function_hint": _pick(
            _capture(r"function:\s*([^\n]+)"),
            _capture(r"ground_truth\.function:\s*([^\n]+)"),
            _capture(r"Vulnerability function:\s*([^\n]+)"),
        ) or "(not provided)",
        "vulnerability_type": _pick(
            _capture(r"Vulnerability type:\s*([^\n]+)"),
            _capture(r"ground_truth\.type:\s*([^\n]+)"),
        ) or "(not provided)",
        "vulnerability_file": _pick(
            _capture(r"Vulnerability file:\s*([^\n]+)"),
            _capture(r"ground_truth\.file:\s*([^\n]+)"),
        ) or "(not provided)",
        "vulnerability_function": _pick(
            _capture(r"Vulnerability function:\s*([^\n]+)"),
            _capture(r"ground_truth\.function:\s*([^\n]+)"),
        ) or "(not provided)",
        "proxy_hint": _pick(hidden.get("proxy_address")) or "(none)",
        "has_public_source": "true" if bool(hidden.get("has_public_source")) else "false",
        "implementation_hint": _pick(hidden.get("implementation_address")) or "(none)",
    }


def _load_cli_metrics(work_dir: Path, task_type: TaskType) -> dict[str, object]:
    metrics_path = work_dir / f"_{task_type.value}_cli_metrics.json"
    if not metrics_path.exists():
        return {}
    try:
        payload = json.loads(metrics_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_workspace_report(work_dir: Path) -> str | None:
    report_path = work_dir / "report.json"
    if not report_path.exists():
        return None
    text = report_path.read_text(encoding="utf-8", errors="replace").strip()
    return text or None




class CliCodingAgent(BaseAgent):
    """Shared adapter for local coding-agent CLIs."""

    supports_tools = True

    def __init__(
        self,
        model: str | None = None,
        *,
        cli_family: str,
        cli_bin: str | None = None,
        **kwargs,
    ):
        family = str(cli_family).strip()
        if family not in CLI_FAMILY_SPECS:
            supported = ", ".join(sorted(CLI_FAMILY_SPECS))
            raise ValueError(
                f"Unsupported CLI agent family: {family!r}. Expected one of: {supported}"
            )

        spec = CLI_FAMILY_SPECS[family]
        resolved_model = str(model or spec["default_model"])
        default_bin = str(spec["default_bin"])
        if family == "codex_cli" and CODEX_WRAPPER.exists():
            default_bin = str(CODEX_WRAPPER)
        elif family == "claude_code" and CLAUDE_WRAPPER.exists():
            default_bin = str(CLAUDE_WRAPPER)
        elif family == "claude_code":
            for candidate in (
                str(Path.home() / ".nvm" / "versions" / "node" / "v20.20.2" / "bin" / "claude"),
                str(Path.home() / ".local" / "bin" / "claude"),
            ):
                if Path(candidate).exists():
                    default_bin = candidate
                    break
        resolved_bin = (
            cli_bin or default_bin
            if (family == "claude_code" and CLAUDE_WRAPPER.exists())
            else cli_bin or os.environ.get(str(spec["bin_env_var"]), default_bin)
        )

        super().__init__(resolved_model, **kwargs)
        self.cli_family = family
        self.cli_bin = resolved_bin
        self._work_dir_slug = str(spec["work_dir_slug"])
        if "timeout_minutes" not in kwargs:
            raise ValueError("timeout_minutes must be specified in model config")
        self.timeout_minutes = kwargs["timeout_minutes"]
        if "max_turns" not in kwargs:
            raise ValueError("max_turns must be specified in model config")
        self.max_turns = int(kwargs["max_turns"])
        self.bare_mode = bool(kwargs.get("bare_mode", True))
        self._custom_work_dir = "work_dir" in kwargs
        default_work_dir = DETECT_WORKSPACE_DIR / "shared" / self._work_dir_slug
        self.work_dir = Path(kwargs.get("work_dir", default_work_dir))
        self.cwd = Path(kwargs.get("cwd", "."))
        self.benchmark_dir = Path(kwargs.get("benchmark_dir", BENCHMARK_DIR))
        self.permission_mode = kwargs.get("permission_mode", "acceptEdits")
        self.dangerously_skip_permissions = bool(kwargs.get("dangerously_skip_permissions", False))
        self.append_system_prompt = str(kwargs.get("append_system_prompt", "")).strip()
        self.full_auto = bool(kwargs.get("full_auto", True))
        self.dangerously_bypass = bool(
            kwargs.get("dangerously_bypass_approvals_and_sandbox", False)
        )
        self.skip_git_repo_check = bool(kwargs.get("skip_git_repo_check", family == "codex_cli"))
        self.yolo = bool(kwargs.get("yolo", True))
        self.yes_always = bool(kwargs.get("yes_always", True))
        self.no_auto_commits = bool(kwargs.get("no_auto_commits", True))
        self.no_stream = bool(kwargs.get("no_stream", True))
        self.disable_configured_mcp_servers = bool(
            kwargs.get("disable_configured_mcp_servers", family == "codex_cli")
        )
        self.codex_profile = str(
            kwargs.get("codex_profile", os.environ.get("CODEX_PROFILE", ""))
        ).strip()
        # Default to a workspace-scoped sandbox rather than full host access: the
        # agent only needs to read/write its workspace and run the bundled tools.
        # `danger-full-access` remains available via kwargs/env for trusted runs.
        self.codex_sandbox = str(
            kwargs.get(
                "codex_sandbox",
                os.environ.get(
                    "CODEX_SANDBOX",
                    "workspace-write" if family == "codex_cli" else "",
                ),
            )
        ).strip()
        # Do not inherit the full shell environment by default — that would expose
        # LLM/RPC/Etherscan secrets to arbitrary shell commands the agent runs.
        self.codex_inherit_shell_env = bool(
            kwargs.get("codex_inherit_shell_env", False)
        )
        self.proxy_base_url = str(kwargs.get("proxy_base_url", "")).strip()
        # OpenHands-specific settings
        self.openhands_agent_cls = str(kwargs.get("openhands_agent_cls", "CodeActAgent")).strip()
        self.max_iterations = int(kwargs.get("max_iterations", 30))
        self.max_budget_per_task = float(kwargs.get("max_budget_per_task", 4.0))
        self.openhands_base_url = str(kwargs.get("openhands_base_url", "")).strip()

    def codex_sandbox_for_task(self, task_type: TaskType) -> str:
        if self.cli_family != "codex_cli":
            return ""
        return self.codex_sandbox

    def codex_inherit_shell_env_for_task(self, task_type: TaskType) -> bool:
        return self.codex_inherit_shell_env

    def _root_dir(self) -> Path:
        return self.cwd.resolve()

    def _foundry_root(self) -> Path | None:
        root = self._root_dir()
        candidate = resolve_repo_path(root, DEFIHACKLABS_DIR)
        if (candidate / "foundry.toml").exists():
            return candidate
        return None

    def _default_work_dir(self, task_type: TaskType) -> Path:
        root = self._root_dir()
        task_root = {
            TaskType.DETECT: DETECT_WORKSPACE_DIR,
            TaskType.EXPLOIT: EXPLOIT_WORKSPACE_DIR,
            TaskType.PATCH: PATCH_WORKSPACE_DIR,
        }[task_type]
        shared_workspace = root / task_root / self._work_dir_slug / "_shared"
        if task_type == TaskType.DETECT:
            return shared_workspace

        foundry_root = self._foundry_root()
        if foundry_root is None:
            return shared_workspace
        if task_type == TaskType.EXPLOIT:
            return foundry_root / "src" / "test" / "_cli_eval" / self._work_dir_slug
        return foundry_root / "src" / "_cli_eval" / self._work_dir_slug

    def _default_case_workspace(self, task_type: TaskType, case_id: str) -> Path:
        task_root = {
            TaskType.DETECT: DETECT_WORKSPACE_DIR,
            TaskType.EXPLOIT: EXPLOIT_WORKSPACE_DIR,
            TaskType.PATCH: PATCH_WORKSPACE_DIR,
        }[task_type]
        return self._root_dir() / task_root / self._work_dir_slug / case_id / "workspace"

    def _resolve_work_dir(self, task_type: TaskType) -> Path:
        if not self._custom_work_dir:
            return self._default_work_dir(task_type)
        path = self.work_dir
        return path if path.is_absolute() else self._root_dir() / path

    def get_case_workspace(self, task_type: TaskType, case_id: str) -> Path:
        if not case_id:
            return self._resolve_work_dir(task_type)
        if not self._custom_work_dir:
            return self._default_case_workspace(task_type, case_id)
        path = self.work_dir
        resolved = path if path.is_absolute() else self._root_dir() / path
        return resolved

    def _ensure_work_dir(self, task_type: TaskType) -> Path:
        work_dir = self._resolve_work_dir(task_type)
        work_dir.mkdir(parents=True, exist_ok=True)
        return work_dir

    def detect(
        self,
        contract_code: dict[str, str],
        context: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        prompt_fields = _merge_case_prompt_fields(self._root_dir(), self.benchmark_dir, TaskType.DETECT, context, case_id)
        benchmark_input = context.strip() if context else "(no additional case input)"
        work_dir = prepare_workspace(
            self,
            TaskType.DETECT,
            case_id=case_id,
            workspace_dir=workspace_dir,
            case_input_text=benchmark_input,
        )
        local_source_dir = stage_contract_code(work_dir, contract_code)
        prompt = CLI_DETECT_PROMPT.format(**prompt_fields, tool_guide=render_tool_guide(self, TaskType.DETECT, case_id=case_id, chain=str(prompt_fields.get('chain') or ''), contract_address=str(prompt_fields.get('contract_address') or prompt_fields.get('target_contract_address') or ''), proxy_address=str(prompt_fields.get('proxy_address') or prompt_fields.get('proxy_contract_address') or ''), block_number=str(prompt_fields.get('block_number') or '')), type_descriptions=render_type_descriptions())
        raw, session_log_path = run_prompt(
            self,
            prompt,
            task_type=TaskType.DETECT,
            schema_text=DETECT_JSON_SCHEMA,
            work_dir=work_dir,
            exec_cwd=work_dir,
        )
        raw = _load_workspace_report(work_dir) or raw
        session_log_text = ""
        cli_metrics = _load_cli_metrics(work_dir, TaskType.DETECT)
        return AgentResponse(
            task_type=TaskType.DETECT,
            raw_response=raw,
            workspace_dir=str(work_dir),
            session_log_path=session_log_path,
            session_log_text=session_log_text,
            agent_elapsed_seconds=(float(cli_metrics.get("agent_elapsed_seconds")) if cli_metrics.get("agent_elapsed_seconds") is not None else None),
            input_tokens_total=(int(cli_metrics.get("input_tokens_total")) if cli_metrics.get("input_tokens_total") is not None else None),
            output_tokens_total=(int(cli_metrics.get("output_tokens_total")) if cli_metrics.get("output_tokens_total") is not None else None),
            cache_read_input_tokens_total=(int(cli_metrics.get("cache_read_input_tokens_total")) if cli_metrics.get("cache_read_input_tokens_total") is not None else None),
            cache_write_input_tokens_total=(int(cli_metrics.get("cache_write_input_tokens_total")) if cli_metrics.get("cache_write_input_tokens_total") is not None else None),
            vulnerability_type=extract_vuln_type(raw),
            vulnerability_description=raw,
        )

    def exploit(
        self,
        contract_code: dict[str, str],
        vulnerability_hint: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        work_dir = prepare_workspace(
            self,
            TaskType.EXPLOIT,
            case_id=case_id,
            workspace_dir=workspace_dir,
            case_input_text=vulnerability_hint,
            output_name="_exploit.sol",
        )
        local_source_dir = stage_contract_code(work_dir, contract_code)
        exploit_path = work_dir / "_exploit.sol"
        prompt_fields = _merge_case_prompt_fields(self._root_dir(), self.benchmark_dir, TaskType.EXPLOIT, vulnerability_hint, case_id)
        prompt = CLI_EXPLOIT_PROMPT.format(
            **prompt_fields,
            exploit_path=exploit_path,
            tool_guide=render_tool_guide(self, TaskType.EXPLOIT, case_id=case_id, chain=str(prompt_fields.get('chain') or ''), contract_address=str(prompt_fields.get('contract_address') or prompt_fields.get('target_contract_address') or ''), proxy_address=str(prompt_fields.get('proxy_address') or prompt_fields.get('proxy_contract_address') or ''), block_number=str(prompt_fields.get('block_number') or ''), exploit_path=exploit_path.name),
            type_descriptions=render_type_descriptions(),
        )
        raw, session_log_path = run_prompt(
            self,
            prompt,
            task_type=TaskType.EXPLOIT,
            schema_text=EXPLOIT_OUTPUT_SCHEMA,
            work_dir=work_dir,
            exec_cwd=work_dir,
        )
        raw = _load_workspace_report(work_dir) or raw
        session_log_text = ""
        cli_metrics = _load_cli_metrics(work_dir, TaskType.EXPLOIT)
        exploit_code = (
            exploit_path.read_text(errors="replace")
            if exploit_path.exists()
            else extract_code_block(raw)
        )
        return AgentResponse(
            task_type=TaskType.EXPLOIT,
            raw_response=raw,
            workspace_dir=str(work_dir),
            session_log_path=session_log_path,
            session_log_text=session_log_text,
            agent_elapsed_seconds=(float(cli_metrics.get("agent_elapsed_seconds")) if cli_metrics.get("agent_elapsed_seconds") is not None else None),
            input_tokens_total=(int(cli_metrics.get("input_tokens_total")) if cli_metrics.get("input_tokens_total") is not None else None),
            output_tokens_total=(int(cli_metrics.get("output_tokens_total")) if cli_metrics.get("output_tokens_total") is not None else None),
            cache_read_input_tokens_total=(int(cli_metrics.get("cache_read_input_tokens_total")) if cli_metrics.get("cache_read_input_tokens_total") is not None else None),
            cache_write_input_tokens_total=(int(cli_metrics.get("cache_write_input_tokens_total")) if cli_metrics.get("cache_write_input_tokens_total") is not None else None),
            exploit_code=exploit_code,
        )

    def fix(
        self,
        contract_code: dict[str, str],
        vulnerability_description: str = "",
        *,
        case_id: str = "",
        workspace_dir: str = "",
    ) -> AgentResponse:
        prompt_fields = _merge_case_prompt_fields(self._root_dir(), self.benchmark_dir, TaskType.PATCH, vulnerability_description, case_id)
        work_dir = prepare_workspace(
            self,
            TaskType.PATCH,
            case_id=case_id,
            workspace_dir=workspace_dir,
            case_input_text=vulnerability_description,
            output_name="_patched.sol",
        )
        local_source_dir = stage_contract_code(work_dir, contract_code)
        patched_path = work_dir / "_patched.sol"
        prompt = CLI_PATCH_PROMPT.format(
            **prompt_fields,
            patched_path=patched_path,
            tool_guide=render_tool_guide(self, TaskType.PATCH, case_id=case_id, chain=str(prompt_fields.get('chain') or ''), contract_address=str(prompt_fields.get('contract_address') or prompt_fields.get('target_contract_address') or ''), block_number=str(prompt_fields.get('block_number') or ''), fixed_path=patched_path.name),
            type_descriptions=render_type_descriptions(),
        )
        raw, session_log_path = run_prompt(
            self,
            prompt,
            task_type=TaskType.PATCH,
            schema_text=PATCH_OUTPUT_SCHEMA,
            work_dir=work_dir,
            exec_cwd=work_dir,
        )
        raw = _load_workspace_report(work_dir) or raw
        session_log_text = ""
        cli_metrics = _load_cli_metrics(work_dir, TaskType.PATCH)
        fix_plan = extract_fix_plan(raw)
        fixed_code = (
            patched_path.read_text(errors="replace")
            if patched_path.exists()
            else extract_code_block(raw)
        )
        return AgentResponse(
            task_type=TaskType.PATCH,
            raw_response=raw,
            workspace_dir=str(work_dir),
            session_log_path=session_log_path,
            session_log_text=session_log_text,
            agent_elapsed_seconds=(float(cli_metrics.get("agent_elapsed_seconds")) if cli_metrics.get("agent_elapsed_seconds") is not None else None),
            input_tokens_total=(int(cli_metrics.get("input_tokens_total")) if cli_metrics.get("input_tokens_total") is not None else None),
            output_tokens_total=(int(cli_metrics.get("output_tokens_total")) if cli_metrics.get("output_tokens_total") is not None else None),
            cache_read_input_tokens_total=(int(cli_metrics.get("cache_read_input_tokens_total")) if cli_metrics.get("cache_read_input_tokens_total") is not None else None),
            cache_write_input_tokens_total=(int(cli_metrics.get("cache_write_input_tokens_total")) if cli_metrics.get("cache_write_input_tokens_total") is not None else None),
            fixed_code=fixed_code,
            file_patches=extract_named_code_blocks(raw),
            fix_description=raw,
            fix_possible=fix_plan.get("fix_possible"),
            fix_rationale=str(fix_plan.get("rationale") or "") or None,
            fix_target_contracts=list(fix_plan.get("target_contracts") or []),
        )
