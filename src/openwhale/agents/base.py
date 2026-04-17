"""智能体基类与通用执行框架。"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

from loguru import logger
from mcp import ClientSession

from ..util.cache import ResultCache
from ..util.context_manager import ContextManager
from ..util.mcp_client import call_tool, list_tools
from ..util.notes import GlobalIntel, PentestNotes
from ..util.poc_index import PocIndex
from ..util.vuln_kb import VulnKnowledgeBase
from .prompts import MISSION_PROMPT, SYSTEM_PROMPT

# 断网比赛环境中，LiteLLM 尝试访问外网获取模型成本表会超时卡死
import os as _os
_os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

MAX_ITERATIONS_DEFAULT = 50


@dataclass(slots=True)
class AgentToolCall:
    """统一工具调用描述。"""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class AgentRunResult:
    """智能体执行结果。"""

    final_message: str
    iterations: int

    def __str__(self) -> str:
        return self.final_message


class BaseChallengeAgent(ABC):
    """渗透挑战赛智能体基类。"""

    def __init__(
        self,
        model_name: str,
        max_iterations: int = MAX_ITERATIONS_DEFAULT,
        on_message: Callable[[str, str], None] | None = None,
        notes: PentestNotes | None = None,
        cache: ResultCache | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        poc_index: PocIndex | None = None,
        intel: GlobalIntel | None = None,
    ) -> None:
        self.model_name = model_name
        self.max_iterations = max_iterations
        self.on_message = on_message
        self.notes = notes or PentestNotes()
        self.cache = cache or ResultCache()
        self.vuln_kb = vuln_kb or VulnKnowledgeBase()
        self.poc_index = poc_index or PocIndex()
        self.intel = intel or GlobalIntel()
        self._submit_failures: dict[str, int] = {}
        self._ctx_manager = ContextManager()

    def _emit(self, role: str, content: str) -> None:
        logger.info(f"[{role.upper()}] {content[:200]}{'...' if len(content) > 200 else ''}")
        if self.on_message:
            self.on_message(role, content)

    def build_initial_messages(self) -> list[dict[str, Any]]:
        """构建首轮消息。子类可覆盖以适配不同基座的消息格式。"""
        notes_context = self.notes.get_all_notes_summary()
        cache_context = self.cache.get_all_recon_summary()
        solved_codes = self.notes.get_solved_codes()

        context_block = ""
        if notes_context and notes_context != "暂无任何笔记。":
            context_block += f"\n\n=== 历史笔记摘要 ===\n{notes_context}"
        if cache_context and cache_context != "暂无侦察缓存。":
            context_block += f"\n\n=== 侦察缓存摘要 ===\n{cache_context}"
        if solved_codes:
            context_block += f"\n\n=== 已解决的赛题 ===\n{', '.join(solved_codes)}"

        mission = MISSION_PROMPT
        if context_block:
            mission += (
                f"\n\n★★★ 检测到历史数据，这是续跑模式 ★★★"
                f"{context_block}"
                f"\n\n续跑核心策略："
                f"\n1. 已解决的题目直接跳过，不要重新启动"
                f"\n2. 未解决的题目先 read_notes 回顾之前的发现和失败尝试"
                f"\n3. 严禁重复之前已失败的方法，必须探索新的攻击面"
                f"\n4. 优先深挖之前发现但没深入的线索（如泄露的凭据、可疑路径、半成品exploit）"
                f"\n5. 尝试之前没测试过的漏洞类型和参数组合"
            )

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": mission},
        ]

    @abstractmethod
    def format_tools(self, tools: list[Any]) -> Any:
        """将 MCP 工具映射到当前基座所需的工具格式。"""

    @abstractmethod
    async def complete_turn(self, messages: list[dict[str, Any]], tools: Any) -> tuple[str, list[AgentToolCall]]:
        """执行一轮模型推理，返回文本与工具调用。"""

    async def run_competition(self, mcp_session: ClientSession) -> AgentRunResult:
        """执行闯关流程并返回最终结果。"""
        logger.info("=== 开始闯关流程 ===")

        tools = await list_tools(mcp_session)
        model_tools = self.format_tools(tools)

        messages = self.build_initial_messages()
        self._emit("system", f"模型已就绪: {self.model_name} | max_iterations={self.max_iterations}")
        self._emit("user", MISSION_PROMPT)

        final_response = ""
        iteration_count = 0
        for iteration in range(self.max_iterations):
            iteration_count = iteration + 1
            logger.debug(f"迭代轮次: {iteration_count}/{self.max_iterations}")

            if self._ctx_manager.should_compact(messages):
                stats = self._ctx_manager.get_stats(messages)
                self._emit("system", f"[上下文管理] 触发压缩: {stats['estimated_tokens']} tokens / {stats['context_window']} 窗口")
                messages = self._ctx_manager.compact(messages, keep_last_n=8)

            assistant_text, tool_calls = await self.complete_turn(messages, model_tools)
            assistant_message: dict[str, Any] = {"role": "assistant", "content": assistant_text or None}
            if tool_calls:
                assistant_message["tool_calls"] = [
                    {
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.name,
                            "arguments": json.dumps(tool_call.arguments, ensure_ascii=False),
                        },
                    }
                    for tool_call in tool_calls
                ]
            messages.append(assistant_message)

            if assistant_text:
                self._emit("assistant", assistant_text)
                final_response = assistant_text

            if not tool_calls:
                logger.info("智能体无更多工具调用，流程结束")
                break

            for tool_call in tool_calls:
                self._emit("tool_call", f"调用工具: {tool_call.name}，参数: {json.dumps(tool_call.arguments, ensure_ascii=False)}")

                result_text = await self._dispatch_tool_call(mcp_session, tool_call)

                self._record_submit_feedback(tool_call.name, tool_call.arguments, result_text, messages)

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result_text,
                    }
                )
        else:
            logger.warning(f"达到最大迭代次数 {self.max_iterations}，强制停止")

        return AgentRunResult(final_message=final_response, iterations=iteration_count)

    async def _dispatch_tool_call(
        self, mcp_session: ClientSession, tool_call: AgentToolCall
    ) -> str:
        """分发工具调用：MCP 工具走 MCP，本地工具走本地处理。"""
        name = tool_call.name
        args = tool_call.arguments

        local_handlers = {
            "search_vuln_kb": lambda: self.vuln_kb.search(args.get("query", "")),
            "get_payloads": lambda: self.vuln_kb.get_payloads(args.get("vuln_type", "")),
            "get_tool_commands": lambda: self.vuln_kb.get_tool_commands(
                args.get("tool_name", ""), args.get("target", "TARGET")
            ),
            "save_note": lambda: self.notes.save_challenge_note(
                args.get("code", ""), args.get("category", "misc"), args.get("content", "")
            ),
            "read_notes": lambda: self.notes.get_challenge_notes(args.get("code", "")),
            "save_recon": lambda: self.cache.save_recon(
                args.get("code", ""), args.get("category", ""), args.get("data", "")
            ),
            "read_recon": lambda: self.cache.get_recon(
                args.get("code", ""), args.get("category")
            ),
            "search_poc_kb": lambda: self.poc_index.search(args.get("query", "")),
            "read_poc_file": lambda: self.poc_index.read_file(args.get("filepath", "")),
            "auto_recon": lambda: f"auto_recon 已移除。请用 Bash(curl/python3) 手动执行侦察步骤。",
        }

        handler = local_handlers.get(name)
        if handler:
            try:
                result_text = handler()
                self._emit("tool_result", f"[{name}] 结果: {result_text[:500]}")
                return result_text
            except Exception as exc:  # noqa: BLE001
                result_text = f"本地工具调用失败: {exc}"
                logger.error(f"工具 {name} 调用失败: {exc}")
                return result_text

        try:
            result = await call_tool(mcp_session, name, args)
            result_text = _extract_tool_result(result)
            self._emit("tool_result", f"[{name}] 结果: {result_text[:500]}")
            return result_text
        except Exception as exc:  # noqa: BLE001
            result_text = f"工具调用失败: {exc}"
            logger.error(f"工具 {name} 调用失败: {exc}")
            return result_text

    def _record_submit_feedback(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result_text: str,
        messages: list[dict[str, Any]],
    ) -> None:
        """当 flag 提交失败时，向模型注入更明确的纠错反馈，避免无效猜测循环。"""
        if tool_name != "submit_flag":
            return

        code = str(arguments.get("code", ""))
        flag = str(arguments.get("flag", ""))
        if not code:
            return

        if '"correct": true' in result_text or "答案正确" in result_text:
            self.notes.record_solved(code, flag)
            return

        if '"correct": false' in result_text or "答案错误" in result_text:
            self.notes.record_attempt(code, f"submit_flag: {flag}", "失败")
            failures = self._submit_failures.get(code, 0) + 1
            self._submit_failures[code] = failures

            if failures >= 2:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"赛题 {code} 的 flag 已连续提交失败 {failures} 次。"
                            "停止继续盲猜，必须回到信息收集、页面分析、参数探测或提示信息复核。"
                            "使用 search_vuln_kb 检索相关漏洞知识，换一个攻击方向。"
                        ),
                    }
                )


def _extract_tool_result(result: Any) -> str:
    """从 MCP 工具调用结果中提取文本内容。"""
    if result is None:
        return "无返回结果"

    if hasattr(result, "content"):
        contents = result.content
        if isinstance(contents, list):
            parts = []
            for item in contents:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif hasattr(item, "data"):
                    parts.append(str(item.data))
                else:
                    parts.append(str(item))
            return "\n".join(parts)
        return str(contents)

    return str(result)


# ── 本地工具定义（OpenAI function calling 格式）──────────────────

LOCAL_TOOLS_OPENAI_FORMAT: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_vuln_kb",
            "description": "搜索漏洞知识库，根据关键词检索漏洞类型、检测方法、Payload模板和工具命令。例如: 'sql injection', 'ssti', 'file upload', '命令注入'",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "搜索关键词"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_payloads",
            "description": "获取特定漏洞类型的全部Payload列表。可用类型: sqli, xss, cmdi, lfi, upload, ssrf, ssti, deser, idor, jwt, xxe, infoleak, auth, cloud, privesc, lateral, cve_common, ai_infra",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型ID"}
                },
                "required": ["vuln_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_tool_commands",
            "description": "获取渗透工具的常用命令模板。可用工具: nmap, ffuf, dirsearch, sqlmap, nuclei, curl",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "工具名称"},
                    "target": {"type": "string", "description": "目标地址", "default": "TARGET"},
                },
                "required": ["tool_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_note",
            "description": "保存赛题相关的笔记(持久化，跨运行可用)。category建议: recon/vuln/exploit/credential/path/param/error",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "赛题code"},
                    "category": {"type": "string", "description": "笔记类别"},
                    "content": {"type": "string", "description": "笔记内容"},
                },
                "required": ["code", "category", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_notes",
            "description": "读取某道赛题的全部历史笔记",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "赛题code"}
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_recon",
            "description": "缓存侦察结果(如目录扫描、端口扫描、技术栈识别)",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "赛题code"},
                    "category": {"type": "string", "description": "缓存类别(如 dirs/ports/headers/tech_stack)"},
                    "data": {"type": "string", "description": "缓存数据"},
                },
                "required": ["code", "category", "data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon",
            "description": "读取侦察缓存。不指定category返回全部",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "赛题code"},
                    "category": {"type": "string", "description": "缓存类别(可选)"},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_poc_kb",
            "description": "搜索外部POC知识库(含3000+漏洞POC文档)。支持CVE编号、产品名、厂商名、漏洞类型等检索。例如: 'CVE-2021-44228', '用友NC', 'Fastjson', 'Confluence RCE', '泛微OA文件上传'",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "搜索关键词(CVE编号/产品名/厂商名/漏洞类型)"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_poc_file",
            "description": "读取POC知识库中某个文件的完整内容(由search_poc_kb返回的路径)",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "POC文件的完整路径"}
                },
                "required": ["filepath"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "auto_recon",
            "description": "[已废弃] 请用 Bash(curl/python3) 手动执行侦察步骤。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "目标URL (如 http://TARGET:PORT)"}
                },
                "required": ["target_url"],
            },
        },
    },
]
