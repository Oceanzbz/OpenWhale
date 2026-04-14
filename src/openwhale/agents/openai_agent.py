"""OpenAI 兼容智能体实现 - 支持 Bash 工具和本地辅助工具。"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger
from openai import OpenAI

from ..util.cache import ResultCache
from ..util.mcp_client import tools_to_openai_format
from ..util.notes import PentestNotes
from ..util.vuln_kb import VulnKnowledgeBase
from .base import (
    LOCAL_TOOLS_OPENAI_FORMAT,
    MAX_ITERATIONS_DEFAULT,
    AgentToolCall,
    AgentRunResult,
    BaseChallengeAgent,
    _extract_tool_result,
)
from .prompts import MISSION_PROMPT, SYSTEM_PROMPT


BASH_TOOL_OPENAI: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "Bash",
        "description": (
            "在本地执行 Bash 命令，用于远程渗透侦察和利用。"
            "支持 curl, python3, nmap, sqlmap, ffuf, dirsearch, nuclei, grep, jq 等工具。"
            "用于: HTTP请求、目录扫描、端口扫描、漏洞扫描、编写临时脚本等。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的bash命令"},
                "timeout_seconds": {"type": "integer", "description": "命令超时秒数(默认120)", "default": 120},
            },
            "required": ["command"],
        },
    },
}


class OpenAIChallengeAgent(BaseChallengeAgent):
    """基于 OpenAI Chat Completions 的智能体实现，支持 Bash 和本地辅助工具。"""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        model_name: str,
        max_iterations: int = MAX_ITERATIONS_DEFAULT,
        on_message=None,
        notes: PentestNotes | None = None,
        cache: ResultCache | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        poc_index=None,
    ) -> None:
        super().__init__(
            model_name=model_name,
            max_iterations=max_iterations,
            on_message=on_message,
            notes=notes,
            cache=cache,
            vuln_kb=vuln_kb,
            poc_index=poc_index,
        )
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self._workspace_root = Path(__file__).resolve().parents[3]
        self._bash_timeout = 120
        self._bash_max_output = 12000

    def format_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        mcp_tools = tools_to_openai_format(tools)
        return mcp_tools + [BASH_TOOL_OPENAI] + LOCAL_TOOLS_OPENAI_FORMAT

    async def complete_turn(self, messages: list[dict[str, Any]], tools: Any) -> tuple[str, list[AgentToolCall]]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.2,
            max_tokens=4096,
        )

        msg = response.choices[0].message
        assistant_text = msg.content or ""

        tool_calls: list[AgentToolCall] = []
        for tool_call in msg.tool_calls or []:
            raw_args = tool_call.function.arguments or "{}"
            try:
                arguments = json.loads(raw_args)
            except json.JSONDecodeError:
                logger.warning(f"工具参数解析失败，已回退为空对象: {raw_args}")
                arguments = {}

            tool_calls.append(
                AgentToolCall(
                    id=tool_call.id,
                    name=tool_call.function.name,
                    arguments=arguments,
                )
            )

        return assistant_text, tool_calls

    async def run_competition(self, mcp_session) -> AgentRunResult:
        """执行闯关流程，支持 Bash 和本地工具。"""
        from ..util.mcp_client import call_tool, list_tools

        logger.info("=== 开始 OpenAI 闯关流程 ===")

        tools = await list_tools(mcp_session)
        model_tools = self.format_tools(tools)

        messages = self.build_initial_messages()
        self._emit("system", f"模型已就绪: {self.model_name} | max_iterations={self.max_iterations} | 工具数={len(model_tools)}")
        self._emit("user", MISSION_PROMPT)

        final_response = ""
        iteration_count = 0

        for iteration in range(self.max_iterations):
            iteration_count = iteration + 1
            logger.debug(f"迭代轮次: {iteration_count}/{self.max_iterations}")

            assistant_text, tool_calls = await self.complete_turn(messages, model_tools)
            assistant_message: dict[str, Any] = {"role": "assistant", "content": assistant_text or None}
            if tool_calls:
                assistant_message["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                        },
                    }
                    for tc in tool_calls
                ]
            messages.append(assistant_message)

            if assistant_text:
                self._emit("assistant", assistant_text)
                final_response = assistant_text

            if not tool_calls:
                logger.info("智能体无更多工具调用，流程结束")
                break

            for tc in tool_calls:
                self._emit("tool_call", f"调用工具: {tc.name}，参数: {json.dumps(tc.arguments, ensure_ascii=False)}")

                if tc.name == "Bash":
                    result_text = await self._run_bash(
                        tc.arguments.get("command", ""),
                        timeout_seconds=tc.arguments.get("timeout_seconds"),
                    )
                else:
                    result_text = await self._dispatch_tool_call(mcp_session, tc)

                self._record_submit_feedback(tc.name, tc.arguments, result_text, messages)

                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": result_text}
                )
        else:
            logger.warning(f"达到最大迭代次数 {self.max_iterations}，强制停止")

        return AgentRunResult(final_message=final_response, iterations=iteration_count)

    async def _run_bash(self, command: str, timeout_seconds: int | None = None) -> str:
        """执行 Bash 命令并返回结果。"""
        timeout = timeout_seconds or self._bash_timeout
        workdir = self._workspace_root

        def _execute() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-lc", command],
                cwd=str(workdir), capture_output=True, text=True, timeout=timeout,
            )

        try:
            proc = await asyncio.to_thread(_execute)
        except subprocess.TimeoutExpired:
            result = json.dumps({"error": f"命令超时(>{timeout}s)", "command": command}, ensure_ascii=False)
            self._emit("tool_result", f"[Bash] {result[:500]}")
            return result
        except Exception as exc:  # noqa: BLE001
            result = json.dumps({"error": str(exc), "command": command}, ensure_ascii=False)
            self._emit("tool_result", f"[Bash] {result[:500]}")
            return result

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if len(stdout) > self._bash_max_output:
            stdout = stdout[: self._bash_max_output] + "\n... [truncated]"
        if len(stderr) > self._bash_max_output:
            stderr = stderr[: self._bash_max_output] + "\n... [truncated]"

        result = json.dumps(
            {"command": command, "returncode": proc.returncode, "stdout": stdout, "stderr": stderr},
            ensure_ascii=False, indent=2,
        )
        self._emit("tool_result", f"[Bash] {result[:500]}")
        return result
