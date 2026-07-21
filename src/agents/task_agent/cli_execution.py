"""Execution helpers for local coding-agent CLIs."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .base import TaskType
from .transport import use_mcp_transport
from infra.secrets import redact_command
from web3mcp.config import write_claude_mcp_config


def _extract_claude_stream_output(text: str) -> str:
    parts: list[str] = []
    for raw_line in str(text or '').splitlines():
        line = raw_line.strip()
        if not line.startswith('{'):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        def add_text(value):
            if isinstance(value, str) and value:
                parts.append(value)
            elif isinstance(value, list):
                for item in value:
                    add_text(item)
            elif isinstance(value, dict):
                if value.get('type') == 'text' and isinstance(value.get('text'), str):
                    parts.append(value['text'])
                for key in ('text', 'delta', 'content', 'message', 'result', 'output'):
                    if key in value:
                        add_text(value.get(key))

        for key in ('content', 'message', 'delta', 'result', 'output', 'text'):
            if key in payload:
                add_text(payload.get(key))
    cleaned = ''.join(parts).strip()
    return cleaned


def _extract_claude_stream_metrics(text: str) -> dict[str, int]:
    totals = {
        "input_tokens_total": 0,
        "output_tokens_total": 0,
        "cache_read_input_tokens_total": 0,
        "cache_write_input_tokens_total": 0,
    }

    def _add_if_int(key: str, value: object) -> None:
        if isinstance(value, int):
            totals[key] += value

    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        message = payload.get("message")
        if isinstance(message, dict):
            usage = message.get("usage")
            if isinstance(usage, dict):
                _add_if_int("input_tokens_total", usage.get("input_tokens"))
                _add_if_int("output_tokens_total", usage.get("output_tokens"))
                _add_if_int("cache_read_input_tokens_total", usage.get("cache_read_input_tokens"))
                _add_if_int("cache_write_input_tokens_total", usage.get("cache_creation_input_tokens"))

        event = payload.get("event")
        if isinstance(event, dict):
            metrics = event.get("amazon-bedrock-invocationMetrics")
            if isinstance(metrics, dict):
                _add_if_int("input_tokens_total", metrics.get("inputTokenCount"))
                _add_if_int("output_tokens_total", metrics.get("outputTokenCount"))
                _add_if_int("cache_read_input_tokens_total", metrics.get("cacheReadInputTokenCount"))
                _add_if_int("cache_write_input_tokens_total", metrics.get("cacheWriteInputTokenCount"))

    return totals


def _extract_codex_session_metrics(text: str) -> dict[str, int | None]:
    """Extract token counts from Codex CLI session JSONL (token_count events)."""
    result: dict[str, int | None] = {
        "input_tokens_total": None,
        "output_tokens_total": None,
        "cache_read_input_tokens_total": None,
        "cache_write_input_tokens_total": None,
    }
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("type") != "event_msg":
            continue
        payload = obj.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "token_count":
            continue
        info = payload.get("info")
        if not isinstance(info, dict):
            continue
        total_usage = info.get("total_token_usage")
        if not isinstance(total_usage, dict):
            continue
        result["input_tokens_total"] = total_usage.get("input_tokens")
        result["output_tokens_total"] = total_usage.get("output_tokens")
        result["cache_read_input_tokens_total"] = total_usage.get("cached_input_tokens")
    return result


def _extract_gemini_stream_metrics(text: str) -> dict[str, int | None]:
    """Extract token counts from Gemini CLI stream-json output (result event with stats)."""
    result: dict[str, int | None] = {
        "input_tokens_total": None,
        "output_tokens_total": None,
        "cache_read_input_tokens_total": None,
        "cache_write_input_tokens_total": None,
    }
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "result":
            continue
        stats = obj.get("stats")
        if not isinstance(stats, dict):
            continue
        if "input_tokens" in stats:
            result["input_tokens_total"] = int(stats["input_tokens"])
        if "output_tokens" in stats:
            result["output_tokens_total"] = int(stats["output_tokens"])
        if "cached" in stats:
            result["cache_read_input_tokens_total"] = int(stats["cached"])
    return result


def _extract_aider_session_metrics(text: str) -> dict[str, int | None]:
    """Extract token counts from Aider stdout (Tokens: ... sent, ... received lines)."""
    import re

    result: dict[str, int | None] = {
        "input_tokens_total": None,
        "output_tokens_total": None,
        "cache_read_input_tokens_total": None,
        "cache_write_input_tokens_total": None,
    }
    total_sent = 0
    total_received = 0
    total_cache_write = 0
    total_cache_hit = 0
    found = False

    def _parse_token_count(s: str) -> int:
        s = s.strip().replace(",", "").lower()
        if s.endswith("k"):
            return int(float(s[:-1]) * 1000)
        return int(float(s))

    for line in str(text or "").splitlines():
        if "Tokens:" not in line:
            continue
        found = True
        sent_match = re.search(r"([\d,.]+k?)\s+sent", line, re.IGNORECASE)
        recv_match = re.search(r"([\d,.]+k?)\s+received", line, re.IGNORECASE)
        cache_write_match = re.search(r"([\d,.]+k?)\s+cache write", line, re.IGNORECASE)
        cache_hit_match = re.search(r"([\d,.]+k?)\s+cache hit", line, re.IGNORECASE)
        if sent_match:
            total_sent += _parse_token_count(sent_match.group(1))
        if recv_match:
            total_received += _parse_token_count(recv_match.group(1))
        if cache_write_match:
            total_cache_write += _parse_token_count(cache_write_match.group(1))
        if cache_hit_match:
            total_cache_hit += _parse_token_count(cache_hit_match.group(1))

    if found:
        result["input_tokens_total"] = total_sent
        result["output_tokens_total"] = total_received
        if total_cache_hit:
            result["cache_read_input_tokens_total"] = total_cache_hit
        if total_cache_write:
            result["cache_write_input_tokens_total"] = total_cache_write
    return result


def _extract_openhands_metrics(work_dir: Path) -> dict[str, int | float | None]:
    """Extract token/cost from OpenHands trajectory JSON saved in work_dir."""
    result: dict[str, int | float | None] = {
        "input_tokens_total": None,
        "output_tokens_total": None,
        "cache_read_input_tokens_total": None,
        "cache_write_input_tokens_total": None,
    }
    trajectory_dir = work_dir / "_openhands_trajectories"
    if not trajectory_dir.exists():
        return result
    trajectory_files = sorted(trajectory_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not trajectory_files:
        return result
    try:
        data = json.loads(trajectory_files[0].read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return result
    if not isinstance(data, list):
        return result

    # Find the last entry with llm_metrics (contains accumulated_token_usage)
    for entry in reversed(data):
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("llm_metrics")
        if not isinstance(metrics, dict):
            continue
        # Primary: accumulated_token_usage has the session totals
        acc = metrics.get("accumulated_token_usage")
        if isinstance(acc, dict):
            prompt = acc.get("prompt_tokens")
            completion = acc.get("completion_tokens")
            cache_read = acc.get("cache_read_tokens")
            cache_write = acc.get("cache_write_tokens")
            if prompt is not None:
                result["input_tokens_total"] = int(prompt)
            if completion is not None:
                result["output_tokens_total"] = int(completion)
            if cache_read:
                result["cache_read_input_tokens_total"] = int(cache_read)
            if cache_write:
                result["cache_write_input_tokens_total"] = int(cache_write)
            return result
        # Fallback: sum from token_usages list
        usages = metrics.get("token_usages")
        if isinstance(usages, list) and usages:
            total_input = sum(int(u.get("prompt_tokens", 0) or 0) for u in usages if isinstance(u, dict))
            total_output = sum(int(u.get("completion_tokens", 0) or 0) for u in usages if isinstance(u, dict))
            total_cache = sum(int(u.get("cache_read_tokens", 0) or 0) for u in usages if isinstance(u, dict))
            if total_input or total_output:
                result["input_tokens_total"] = total_input
                result["output_tokens_total"] = total_output
                if total_cache:
                    result["cache_read_input_tokens_total"] = total_cache
            return result
    return result


def _write_cli_metrics(metrics_path: Path, *, elapsed_seconds: float, session_log_text: str, cli_family: str, work_dir: Path | None = None) -> None:
    payload: dict[str, object] = {
        "agent_elapsed_seconds": round(max(elapsed_seconds, 0.0), 6),
        "input_tokens_total": None,
        "output_tokens_total": None,
        "cache_read_input_tokens_total": None,
        "cache_write_input_tokens_total": None,
    }
    if cli_family == "claude_code":
        payload.update(_extract_claude_stream_metrics(session_log_text))
    elif cli_family == "codex_cli":
        payload.update(_extract_codex_session_metrics(session_log_text))
    elif cli_family == "gemini_cli":
        payload.update(_extract_gemini_stream_metrics(session_log_text))
    elif cli_family == "aider":
        payload.update(_extract_aider_session_metrics(session_log_text))
    elif cli_family == "openhands" and work_dir is not None:
        payload.update(_extract_openhands_metrics(work_dir))
    try:
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _find_codex_session_file(cwd: Path) -> Path | None:
    """Find the most recent Codex session JSONL whose cwd matches *cwd*.

    Scans today's and yesterday's session directories to handle midnight
    boundary crossings.  Relies solely on cwd matching (each workspace path
    is unique per run) so no wall-clock comparison is needed.
    """
    import datetime as _dt

    sessions_root = Path.home() / ".codex" / "sessions"
    if not sessions_root.exists():
        return None

    today = _dt.datetime.now(_dt.timezone.utc)
    day_dirs = [
        sessions_root / today.strftime("%Y/%m/%d"),
        sessions_root / (today - _dt.timedelta(days=1)).strftime("%Y/%m/%d"),
    ]

    cwd_str = str(cwd.resolve())
    best: Path | None = None
    best_mtime = 0.0
    for day_dir in day_dirs:
        if not day_dir.exists():
            continue
        for candidate in day_dir.glob("rollout-*.jsonl"):
            try:
                mtime = candidate.stat().st_mtime
                if mtime <= best_mtime:
                    continue
                first_line = candidate.open().readline()
                meta = json.loads(first_line)
                if meta.get("type") == "session_meta":
                    session_cwd = meta.get("payload", {}).get("cwd", "")
                    if session_cwd == cwd_str:
                        best = candidate
                        best_mtime = mtime
            except (json.JSONDecodeError, OSError):
                continue
    return best


def coerce_process_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def cleanup_file(path: Path) -> None:
    if path.exists():
        path.unlink()


def _native_mcp_env(agent: Any) -> dict[str, str]:
    from web3mcp.config import _server_env

    env = _server_env(agent._root_dir())
    benchmark_dir = getattr(agent, "benchmark_dir", None)
    if benchmark_dir:
        bench_path = Path(benchmark_dir)
        if not bench_path.is_absolute():
            bench_path = (agent._root_dir() / bench_path).resolve()
        else:
            bench_path = bench_path.resolve()
        env["W3BB_BENCHMARK_DIR"] = str(bench_path)
    return env


def _write_openhands_config(agent: Any, work_dir: Path) -> Path:
    """Generate a config.toml for OpenHands with the agent's LLM settings."""
    model = agent.model
    config_path = work_dir / "_openhands_config.toml"

    # Determine API key env var based on model prefix
    api_key_env = ""
    if model.startswith("anthropic/"):
        api_key_env = os.environ.get("ANTHROPIC_API_KEY", "")
    elif model.startswith("openai/") or model.startswith("gpt"):
        api_key_env = os.environ.get("OPENAI_API_KEY", "")
    elif model.startswith("bedrock/") or model.startswith("us.anthropic"):
        api_key_env = ""  # bedrock uses AWS creds
    elif model.startswith("gemini/") or model.startswith("google/"):
        api_key_env = os.environ.get("GOOGLE_API_KEY", os.environ.get("GEMINI_API_KEY", ""))
    else:
        api_key_env = os.environ.get("ANTHROPIC_API_KEY", os.environ.get("OPENAI_API_KEY", ""))

    base_url = getattr(agent, "openhands_base_url", "") or ""
    aws_region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

    trajectory_dir = work_dir / "_openhands_trajectories"
    trajectory_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "[core]",
        f'workspace_base = "{work_dir}"',
        f"max_iterations = {getattr(agent, 'max_iterations', 30)}",
        f"max_budget_per_task = {getattr(agent, 'max_budget_per_task', 4.0)}",
        f'save_trajectory_path = "{trajectory_dir}"',
        "",
        "[llm]",
        f'model = "{model}"',
    ]
    if api_key_env:
        lines.append(f'api_key = "{api_key_env}"')
    if base_url:
        lines.append(f'base_url = "{base_url}"')
    if model.startswith("bedrock/") or model.startswith("us.anthropic"):
        lines.append(f'aws_region_name = "{aws_region}"')
    lines.extend([
        "",
        "[sandbox]",
        'base_container_image = "nikolaik/python-nodejs:python3.12-nodejs22-slim"',
        f"timeout = {int(getattr(agent, 'timeout_minutes', 60) * 60)}",
    ])

    config_path.write_text("\n".join(lines) + "\n")
    # Contains the LLM API key in plaintext — owner read/write only.
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    return config_path


def _codex_mcp_overrides(agent: Any, task_type: TaskType, work_dir: Path) -> list[str]:
    env = _native_mcp_env(agent)
    args = [
        "-m",
        "web3mcp.server",
        "--workspace",
        str(work_dir.resolve()),
        "--repo-root",
        str(agent._root_dir().resolve()),
        "--task",
        task_type.value,
    ]
    command = [
        "-c",
        "mcp_servers={}",
        "-c",
        'mcp_servers.web3bug_tools.command="python3"',
        "-c",
        f'mcp_servers.web3bug_tools.args={json.dumps(args)}',
    ]
    for key, value in env.items():
        command.extend(["-c", f'mcp_servers.web3bug_tools.env.{key}={json.dumps(str(value))}'])
    return command


def build_command(
    agent: Any,
    *,
    task_type: TaskType,
    cwd: Path,
    work_dir: Path,
    last_message_path: Path,
    schema_text: str | None,
    mcp_config_path: Path | None = None,
    mcp_overrides: list[str] | None = None,
) -> list[str]:
    if agent.cli_family == "claude_code":
        command = [
            agent.cli_bin,
            "-p",
            "--model",
            agent.model,
            "--output-format",
            "stream-json",
            "--include-partial-messages",
            "--verbose",
            "--permission-mode",
            agent.permission_mode,
        ]
        if getattr(agent, "bare_mode", False) and task_type != TaskType.FILL:
            command.append("--bare")
        if agent.dangerously_skip_permissions:
            command.append("--dangerously-skip-permissions")
        if agent.append_system_prompt:
            command.extend(["--append-system-prompt", agent.append_system_prompt])
        disallowed = [
            "Task", "AskUserQuestion",
            "CronCreate", "CronDelete", "CronList",
            "EnterPlanMode", "ExitPlanMode",
            "EnterWorktree", "ExitWorktree",
            "NotebookEdit", "Skill",
            "TaskOutput", "TaskStop", "TodoWrite",
            "ListMcpResourcesTool", "ReadMcpResourceTool",
            "ScheduleWakeup",
        ]
        if task_type != TaskType.FILL:
            disallowed = ["WebFetch", "WebSearch", "ToolSearch"] + disallowed
        command.extend(["--disallowed-tools"] + disallowed)
        max_turns = getattr(agent, "max_turns", 0)
        if max_turns and max_turns > 0:
            command.extend(["--max-turns", str(max_turns)])
        if mcp_config_path is not None:
            command.extend(["--mcp-config", str(mcp_config_path)])
        return command

    if agent.cli_family == "codex_cli":
        sandbox_resolver = getattr(agent, "codex_sandbox_for_task", None)
        sandbox = (
            str(sandbox_resolver(task_type)).strip()
            if callable(sandbox_resolver)
            else str(getattr(agent, "codex_sandbox", "")).strip()
        )
        inherit_env_resolver = getattr(agent, "codex_inherit_shell_env_for_task", None)
        inherit_shell_env = (
            bool(inherit_env_resolver(task_type))
            if callable(inherit_env_resolver)
            else bool(getattr(agent, "codex_inherit_shell_env", False))
        )
        command = [
            agent.cli_bin,
            "exec",
        ]
        codex_profile = str(getattr(agent, "codex_profile", "")).strip()
        if codex_profile:
            command.extend(["--profile", codex_profile])
        command.extend(
            [
                "--cd",
                str(cwd),
                "--output-last-message",
                str(last_message_path),
                "--model",
                agent.model,
            ]
        )
        if sandbox:
            command.extend(["--sandbox", sandbox])
        if mcp_overrides:
            command.extend(mcp_overrides)
        elif agent.disable_configured_mcp_servers and mcp_config_path is None:
            command.extend(["-c", "mcp_servers={}"])
        if inherit_shell_env:
            command.extend(["-c", "shell_environment_policy.inherit=all"])
        for feat in ("multi_agent", "memories", "plugins", "js_repl"):
            command.extend(["--disable", feat])
        if agent.dangerously_bypass:
            command.append("--dangerously-bypass-approvals-and-sandbox")
        elif agent.full_auto and not sandbox:
            command.append("--full-auto")
        if agent.skip_git_repo_check or mcp_overrides:
            command.append("--skip-git-repo-check")
        instructions_file = cwd / "AGENTS.md"
        if instructions_file.exists():
            command.extend(["-c", f'model_instructions_file="{instructions_file}"'])
        if schema_text:
            schema_path = last_message_path.with_suffix(".schema.json")
            schema_path.write_text(schema_text)
            command.extend(["--output-schema", str(schema_path)])
        command.append("-")
        return command

    if agent.cli_family == "gemini_cli":
        command = [agent.cli_bin, "--model", agent.model, "--output-format", "stream-json"]
        if agent.yolo:
            command.append("--yolo")
        return command

    if agent.cli_family == "aider":
        command = [agent.cli_bin, "--model", agent.model]
        if agent.yes_always:
            command.append("--yes-always")
        if agent.no_auto_commits:
            command.append("--no-auto-commits")
        if agent.no_stream:
            command.append("--no-stream")
        return command

    if agent.cli_family == "opencode":
        return [agent.cli_bin, "run", "--model", agent.model]

    if agent.cli_family == "openhands":
        config_path = _write_openhands_config(agent, work_dir)
        command = [
            agent.cli_bin,
            "-m", "openhands.core.main",
            "--config-file", str(config_path),
            "-d", str(work_dir),
            "-c", getattr(agent, "openhands_agent_cls", "CodeActAgent"),
            "-i", str(getattr(agent, "max_iterations", 30)),
        ]
        return command

    raise ValueError(f"Unsupported CLI agent family: {agent.cli_family}")


def prepare_invocation(
    agent: Any,
    *,
    command: list[str],
    prompt: str,
    task_type: TaskType,
    work_dir: Path,
) -> tuple[list[str], str | None]:
    if agent.cli_family == "aider":
        prompt_path = work_dir / f"_{task_type.value}_aider_prompt.txt"
        prompt_path.write_text(prompt)
        return [*command, "--message-file", str(prompt_path)], None

    if agent.cli_family == "gemini_cli":
        return [*command, "-p", ""], prompt

    if agent.cli_family == "opencode":
        return [*command, prompt], None

    if agent.cli_family == "openhands":
        prompt_path = work_dir / f"_{task_type.value}_openhands_prompt.txt"
        prompt_path.write_text(prompt)
        return [*command, "-f", str(prompt_path)], None

    return command, prompt


def run_prompt(
    agent: Any,
    prompt: str,
    *,
    task_type: TaskType,
    schema_text: str | None = None,
    work_dir: Path | None = None,
    exec_cwd: Path | None = None,
) -> tuple[str, str]:
    cwd = exec_cwd.resolve() if exec_cwd is not None else agent._root_dir()
    work_dir = work_dir.resolve() if work_dir is not None else agent._ensure_work_dir(task_type)
    work_dir.mkdir(parents=True, exist_ok=True)
    active_work_dir = work_dir

    last_message_path = active_work_dir / f"_{task_type.value}_last_message.txt"
    session_log_path = work_dir / f"_{task_type.value}_cli_session.log"
    metrics_path = work_dir / f"_{task_type.value}_cli_metrics.json"
    cleanup_file(last_message_path)
    cleanup_file(session_log_path)
    cleanup_file(metrics_path)
    last_message_snapshot = ""

    # Decide transport: MCP (native tool calls) vs file-IPC bridge
    mcp_capable = getattr(agent, "cli_family", "") in {"codex_cli", "claude_code"}
    mcp_mode = bool(use_mcp_transport()) and mcp_capable and task_type in {TaskType.DETECT, TaskType.EXPLOIT, TaskType.PATCH, TaskType.FILL}
    mcp_config_path: Path | None = None
    mcp_overrides: list[str] | None = None
    if mcp_mode:
        repo_root = agent._root_dir()
        if agent.cli_family == "claude_code":
            mcp_config_path = write_claude_mcp_config(
                active_work_dir, repo_root, task_type.value
            )
        elif agent.cli_family == "codex_cli":
            mcp_overrides = _codex_mcp_overrides(agent, task_type, active_work_dir)

    command = build_command(
        agent,
        task_type=task_type,
        cwd=cwd,
        work_dir=active_work_dir,
        last_message_path=last_message_path,
        schema_text=schema_text,
        mcp_config_path=mcp_config_path,
        mcp_overrides=mcp_overrides,
    )
    command, stdin_input = prepare_invocation(
        agent,
        command=command,
        prompt=prompt,
        task_type=task_type,
        work_dir=active_work_dir,
    )

    # Build env overrides for proxy-based model switching (e.g. CC-Switch)
    proxy_base_url = getattr(agent, "proxy_base_url", "")
    run_env: dict[str, str] | None = None
    if proxy_base_url:
        run_env = {**os.environ, "ANTHROPIC_BASE_URL": proxy_base_url}

    # OpenHands needs LLM API keys in the environment (litellm reads env vars)
    if getattr(agent, "cli_family", "") == "openhands":
        run_env = run_env or {**os.environ}

    preamble = [
        f"[cli_family] {getattr(agent, 'cli_family', '')}",
        f"[task] {task_type.value}",
        f"[cwd] {cwd}",
        f"[workspace] {active_work_dir}",
    ]
    if proxy_base_url:
        preamble.append(f"[proxy] {proxy_base_url}")
    preamble.extend([
        "[command]",
        # Redact secret values (API keys, RPC URLs) embedded in argv before they
        # reach the on-disk session log, which may be archived/shared.
        redact_command(command),
    ])
    if stdin_input:
        preamble.extend(["[prompt]", stdin_input])
    preamble_text = "\n".join(part for part in preamble if part).rstrip() + "\n\n"

    started_at = time.monotonic()
    timeout_seconds = int(agent.timeout_minutes * 60)
    timed_out = False
    try:
        with session_log_path.open("w", encoding="utf-8") as session_log:
            session_log.write(preamble_text)
            session_log.flush()
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                cwd=cwd,
                env=run_env,
                stdout=session_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                if stdin_input:
                    proc.stdin.write(stdin_input)
                    proc.stdin.close()
                else:
                    proc.stdin.close()
                proc.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except OSError:
                        pass
                    proc.wait(timeout=5)
            if last_message_path.exists():
                last_message_snapshot = last_message_path.read_text(errors="replace").strip()
    except Exception:
        pass

    if timed_out:
        output = last_message_snapshot
        if not output and last_message_path.exists():
            output = last_message_path.read_text(errors="replace").strip()
        elif session_log_path.exists():
            output = session_log_path.read_text(errors="replace").strip()

        parts = [output] if output else []
        parts.append(f"[timeout]\nCLI timed out after {timeout_seconds}s")
        timeout_message = "\n".join(part for part in parts if part).strip()
        with session_log_path.open("a", encoding="utf-8") as session_log:
            if session_log.tell() > 0:
                session_log.write("\n")
            session_log.write(timeout_message + "\n")
        session_log_text = session_log_path.read_text(errors="replace").strip() if session_log_path.exists() else timeout_message
        metrics_session_text = session_log_text
        if getattr(agent, "cli_family", "") == "codex_cli":
            codex_session = _find_codex_session_file(cwd)
            if codex_session:
                metrics_session_text = codex_session.read_text(errors="replace").strip()
        _write_cli_metrics(metrics_path, elapsed_seconds=time.monotonic() - started_at, session_log_text=metrics_session_text, cli_family=str(getattr(agent, "cli_family", "")), work_dir=active_work_dir)
        return timeout_message, str(session_log_path)

    output = last_message_snapshot
    if not output and last_message_path.exists():
        output = last_message_path.read_text(errors="replace").strip()
    session_log_text = (
        session_log_path.read_text(errors="replace").strip()
        if session_log_path.exists()
        else ""
    )
    if output and session_log_path.exists() and output not in session_log_text:
        with session_log_path.open("a", encoding="utf-8") as session_log:
            if session_log.tell() > 0:
                session_log.write("\n")
            session_log.write("[final_output]\n" + output + "\n")
        session_log_text = session_log_path.read_text(errors="replace").strip()
    if getattr(agent, "cli_family", "") == "claude_code":
        stream_output = _extract_claude_stream_output(session_log_text)
        if stream_output:
            output = stream_output

    if not output:
        output = session_log_text

    # For Codex CLI, prefer the full session JSONL from ~/.codex/sessions/
    effective_log_path = str(session_log_path)
    metrics_session_text = session_log_text
    if getattr(agent, "cli_family", "") == "codex_cli":
        codex_session = _find_codex_session_file(cwd)
        if codex_session:
            effective_log_path = str(codex_session)
            metrics_session_text = codex_session.read_text(errors="replace").strip()

    _write_cli_metrics(metrics_path, elapsed_seconds=time.monotonic() - started_at, session_log_text=metrics_session_text, cli_family=str(getattr(agent, "cli_family", "")), work_dir=active_work_dir)

    if proc.returncode != 0:
        parts = [output] if output else []
        parts.append(f"[exit code: {proc.returncode}]")
        return "\n".join(part for part in parts if part).strip(), effective_log_path

    return output or "(no output)", effective_log_path
