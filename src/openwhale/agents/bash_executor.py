"""Bash 命令执行器 - 从 deepagents_agent.py 提取。"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path

_FLAG_RE = re.compile(r"flag\{[^}]{1,200}\}")


class BashExecutor:
    """异步 Bash 命令执行器，支持超时和输出截断。

    关键特性：截断输出前自动扫描完整内容中的 flag 模式，
    确保 flag 不会因截断而丢失。
    """

    def __init__(
        self,
        workspace_root: Path,
        timeout_seconds: int = 60,
        max_output_chars: int = 12000,
    ) -> None:
        self._workspace_root = workspace_root
        self._timeout_seconds = timeout_seconds
        self._max_output_chars = max_output_chars
        self.last_flags_found: list[str] = []

    async def run(
        self,
        command: str,
        cwd: str | None = None,
        timeout_seconds: int | None = None,
    ) -> str:
        self.last_flags_found = []
        workdir = Path(cwd).expanduser().resolve() if cwd else self._workspace_root
        timeout = timeout_seconds or self._timeout_seconds

        if not workdir.exists():
            return self._render(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"cwd 不存在: {workdir}",
            )

        def _execute() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-lc", command],
                cwd=str(workdir), capture_output=True, text=True, timeout=timeout,
            )

        try:
            completed = await asyncio.to_thread(_execute)
        except subprocess.TimeoutExpired:
            return self._render(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"命令执行超时（>{timeout} 秒）",
            )
        except Exception as exc:  # noqa: BLE001
            return self._render(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"命令执行失败: {exc}",
            )

        return self._render(
            command=command, cwd=workdir, timeout_seconds=timeout,
            completed_process=completed,
        )

    @staticmethod
    def _scan_flags(text: str) -> list[str]:
        """Scan text for flag{...} patterns and return unique matches."""
        return list(dict.fromkeys(_FLAG_RE.findall(text)))

    def _truncate_with_flag_preservation(self, text: str, label: str) -> str:
        """Truncate text but preserve any flag patterns found in the full content."""
        if len(text) <= self._max_output_chars:
            return text
        flags = self._scan_flags(text)
        truncated = text[: self._max_output_chars] + f"\n... [{label} truncated]"
        if flags:
            self.last_flags_found.extend(flags)
            flag_lines = "\n".join(f"  ★ {f}" for f in flags)
            truncated += (
                f"\n\n★★★ 截断输出中发现 {len(flags)} 个 flag 模式 ★★★\n"
                f"{flag_lines}\n"
                "请立即用 submit_current_flag 提交！"
            )
        return truncated

    def _render(
        self,
        command: str,
        cwd: Path,
        timeout_seconds: int,
        completed_process: subprocess.CompletedProcess[str] | None,
        error: str | None = None,
    ) -> str:
        if error is not None:
            return f"[ERROR] {error}\n$ {command}"

        assert completed_process is not None
        stdout = completed_process.stdout or ""
        stderr = completed_process.stderr or ""

        pre_truncation_flags = self._scan_flags(stdout + stderr)
        self.last_flags_found = pre_truncation_flags

        stdout = self._truncate_with_flag_preservation(stdout, "stdout")
        stderr = self._truncate_with_flag_preservation(stderr, "stderr")

        parts: list[str] = []
        if completed_process.returncode != 0:
            parts.append(f"[exit={completed_process.returncode}]")
        if stdout:
            parts.append(stdout)
        if stderr:
            parts.append(f"[stderr] {stderr}")
        return "\n".join(parts) if parts else "(empty output)"
