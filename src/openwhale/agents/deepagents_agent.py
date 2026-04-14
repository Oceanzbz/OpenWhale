"""DeepAgents 智能体实现 - 主从并发架构 + 笔记/缓存/RAG 工具。"""

from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any
from pathlib import Path

from deepagents import create_deep_agent
from langchain_core.messages import AIMessage, AIMessageChunk
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.errors import GraphRecursionError
from loguru import logger
from mcp import ClientSession

from ..util.cache import ResultCache
from ..util.mcp_client import call_tool
from ..util.notes import PentestNotes
from ..util.vuln_kb import VulnKnowledgeBase
from .base import AgentRunResult, BaseChallengeAgent, MAX_ITERATIONS_DEFAULT
from .prompts import CHILD_MISSION_FIRST_ROUND, CHILD_MISSION_RETRY_ROUND, CHILD_SYSTEM_TEMPLATE, MISSION_PROMPT, SYSTEM_PROMPT


class DeepAgentsChallengeAgent(BaseChallengeAgent):
    """基于 DeepAgents 的挑战赛智能体，支持并发子智能体。"""

    _child_wrapper_tools = {
        "start_current_challenge",
        "stop_current_challenge",
        "view_current_hint",
        "submit_current_flag",
        "refresh_challenge_status",
        "save_challenge_note",
        "read_challenge_notes",
        "read_recon_cache",
        "save_recon_cache",
        "search_vuln_kb",
        "get_payloads",
        "get_tool_commands",
        "search_poc_kb",
        "read_poc_file",
        "auto_recon",
    }

    def __init__(
        self,
        config: dict[str, str],
        max_iterations: int = MAX_ITERATIONS_DEFAULT,
        on_message=None,
        notes: PentestNotes | None = None,
        cache: ResultCache | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        poc_index=None,
    ) -> None:
        model_name = config.get("MODEL_NAME", "MiniMax-M2.7")
        super().__init__(
            model_name=model_name,
            max_iterations=max_iterations,
            on_message=on_message,
            notes=notes,
            cache=cache,
            vuln_kb=vuln_kb,
            poc_index=poc_index,
        )
        self.config = config
        self._mcp_session: ClientSession | None = None
        self._workspace_root = Path(__file__).resolve().parents[3]
        self._tool_call_counters: dict[str, int] = {}
        self._repeat_call_limit = int(config.get("DEEPAGENTS_REPEAT_CALL_LIMIT", "4"))
        self._timeout_seconds = int(config.get("DEEPAGENTS_TIMEOUT_SECONDS", "600"))
        self._recursion_limit = int(
            config.get("DEEPAGENTS_RECURSION_LIMIT", str(max(self.max_iterations * 8, 128)))
        )
        self._trace_enabled = config.get("DEEPAGENTS_TRACE_ENABLED", "false").lower() in ("1", "true", "yes")
        self._trace_verbose = config.get("DEEPAGENTS_TRACE_VERBOSE", "false").lower() in ("1", "true", "yes")
        self._bash_timeout_seconds = int(config.get("DEEPAGENTS_BASH_TIMEOUT_SECONDS", "120"))
        self._bash_max_output_chars = int(config.get("DEEPAGENTS_BASH_MAX_OUTPUT_CHARS", "12000"))
        self._max_concurrent = int(config.get("MAX_CONCURRENT_CHALLENGES", "3"))

    def format_tools(self, tools: list[Any]) -> list[Any]:
        return tools

    async def complete_turn(self, messages: list[dict[str, Any]], tools: Any):  # pragma: no cover
        raise NotImplementedError("DeepAgents backend does not use manual turn completion")

    def _emit_trace_event(self, event: dict[str, Any], emitted_set: set[str]) -> None:
        event_name = str(event.get("event", "unknown"))
        node_name = str(event.get("name", ""))
        data = event.get("data")

        if event_name.endswith("tool_start"):
            if node_name.endswith("_tool") or node_name in self._child_wrapper_tools:
                return
            input_data = data.get("input") if isinstance(data, dict) else data
            self._emit("tool_call", f"调用工具: {node_name or 'tool'}，参数: {str(input_data)[:500]}")
            return

        if event_name.endswith("tool_end"):
            if node_name.endswith("_tool") or node_name in self._child_wrapper_tools:
                return
            output_data = data.get("output") if isinstance(data, dict) else data
            self._emit("tool_result", f"[{node_name or 'tool'}] 结果: {str(output_data)[:500]}")
            return

        if event_name.endswith("llm_end"):
            output_data = data.get("output") if isinstance(data, dict) else data
            for text in self._extract_assistant_texts(output_data):
                if text not in emitted_set:
                    emitted_set.add(text)
                    self._emit("assistant", text)
            if self._trace_enabled:
                self._emit("trace", f"模型结束: {node_name or 'model'} | 输出: {str(output_data)[:300]}")
            return

        if event_name.endswith("chain_stream") or event_name.endswith("llm_stream"):
            chunk = data.get("chunk") if isinstance(data, dict) else data
            for text in self._extract_assistant_texts(chunk):
                if text not in emitted_set:
                    emitted_set.add(text)
                    self._emit("assistant", text)
            if self._trace_enabled and self._trace_verbose:
                text = getattr(chunk, "content", None) or getattr(chunk, "text", None) or str(chunk)
                if text and str(text).strip():
                    self._emit("trace", f"流式片段: {str(text)[:200]}")
            return

        if not self._trace_enabled:
            return
        if event_name.endswith("chain_start"):
            self._emit("trace", f"流程开始: {node_name or 'graph'}")
        elif event_name.endswith("chain_end"):
            self._emit("trace", f"流程结束: {node_name or 'graph'}")
        elif event_name.endswith("llm_start"):
            self._emit("trace", f"模型开始: {node_name or 'model'}")

    async def _collect_final_message(self, result: dict[str, Any], emitted_set: set[str]) -> tuple[str, int]:
        final_response = ""
        iterations = 0
        for message in result.get("messages", []):
            if isinstance(message, AIMessage):
                iterations += 1
                content = message.content
                if isinstance(content, str) and content.strip():
                    final_response = content.strip()
                    if final_response not in emitted_set:
                        emitted_set.add(final_response)
                        self._emit("assistant", final_response)
        return final_response, iterations

    def _extract_assistant_texts(self, payload: Any) -> list[str]:
        texts: list[str] = []

        def _walk(node: Any) -> None:
            if node is None:
                return
            if isinstance(node, (AIMessage, AIMessageChunk)):
                if isinstance(node.content, str) and node.content.strip():
                    texts.append(node.content.strip())
                return
            if isinstance(node, dict):
                role = node.get("role")
                content = node.get("content")
                if role == "assistant" and isinstance(content, str) and content.strip():
                    texts.append(content.strip())
                for value in node.values():
                    _walk(value)
                return
            if isinstance(node, (list, tuple, set)):
                for item in node:
                    _walk(item)

        _walk(payload)
        return texts

    @staticmethod
    def _try_parse_json(text: str) -> dict[str, Any] | None:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except Exception:  # noqa: BLE001
            return None
        return None

    async def _run_streamed_deep_agent(
        self, deep_agent: Any, mission_prompt: str
    ) -> AgentRunResult:
        emitted_set: set[str] = set()
        events: list[dict[str, Any]] = []

        async def _run_stream() -> None:
            async for event in deep_agent.astream_events(
                {"messages": [{"role": "user", "content": mission_prompt}]},
                config={"recursion_limit": self._recursion_limit},
                version="v2",
            ):
                if isinstance(event, dict):
                    events.append(event)
                    self._emit_trace_event(event, emitted_set)

        try:
            await asyncio.wait_for(_run_stream(), timeout=self._timeout_seconds)
        except GraphRecursionError as exc:
            msg = (
                f"DeepAgents 触发递归上限（{self._recursion_limit}），已主动中止。"
                f" 原始错误: {exc}"
            )
            self._emit("system", msg)
            return AgentRunResult(final_message=msg, iterations=0)
        except (TimeoutError, asyncio.TimeoutError):
            msg = (
                f"DeepAgents 执行超时（>{self._timeout_seconds}s），已主动中止。"
            )
            self._emit("system", msg)
            return AgentRunResult(final_message=msg, iterations=0)

        result: dict[str, Any] = {}
        for event in reversed(events):
            if event.get("event", "").endswith("chain_end") and isinstance(event.get("data"), dict):
                maybe_output = event["data"].get("output")
                if isinstance(maybe_output, dict):
                    result = maybe_output
                    break

        if not result:
            result = {"messages": []}

        final_response, iterations = await self._collect_final_message(result, emitted_set)
        return AgentRunResult(final_message=final_response, iterations=iterations)

    async def _run_single_challenge_agent(
        self, model: ChatOpenAI, challenge: dict[str, Any]
    ) -> AgentRunResult:
        code = str(challenge.get("code", ""))
        title = str(challenge.get("title", ""))
        entrypoint = challenge.get("entrypoint")

        # ── 为子智能体构建工具集 ─────────────────────────────────

        @tool
        async def start_current_challenge() -> str:
            """启动当前子智能体绑定的赛题实例。"""
            return await self._call_mcp("start_challenge", {"code": code})

        @tool
        async def stop_current_challenge() -> str:
            """停止当前子智能体绑定的赛题实例。"""
            return await self._call_mcp("stop_challenge", {"code": code})

        @tool
        async def view_current_hint() -> str:
            """查看当前子智能体绑定赛题的提示信息（会扣分，慎用）。"""
            return await self._call_mcp("view_hint", {"code": code})

        @tool
        async def submit_current_flag(flag: str) -> str:
            """提交当前赛题 flag。只有在远程响应中明确看到 flag{...} 时才能提交。"""
            result = await self._call_mcp("submit_flag", {"code": code, "flag": flag})
            if '"correct": true' in result or "答案正确" in result:
                self.notes.record_solved(code, flag)
            else:
                self.notes.record_attempt(code, f"submit_flag: {flag}", "失败")
            return result

        @tool
        async def refresh_challenge_status() -> str:
            """刷新当前题状态，确认是否已得分。"""
            return await self._call_mcp("list_challenges", {})

        @tool("Bash")
        async def bash_tool(command: str, cwd: str | None = None, timeout_seconds: int | None = None) -> str:
            """在本地执行 Bash 命令（用于远程 HTTP 侦察、请求脚本、结果记录）。支持 curl, python3, nmap, sqlmap, ffuf, dirsearch, nuclei, grep, jq 等。"""
            return await self._run_bash(command, cwd=cwd, timeout_seconds=timeout_seconds)

        # ── 笔记/缓存/RAG 工具 ──────────────────────────────────

        notes = self.notes
        result_cache = self.cache
        vuln_kb = self.vuln_kb

        @tool
        async def save_challenge_note(category: str, content: str) -> str:
            """保存赛题笔记(持久化跨运行)。category建议: recon/vuln/exploit/credential/path/param/error"""
            return notes.save_challenge_note(code, category, content)

        @tool
        async def read_challenge_notes() -> str:
            """读取当前赛题的全部历史笔记。"""
            return notes.get_challenge_notes(code)

        @tool
        async def save_recon_cache(category: str, data: str) -> str:
            """缓存侦察结果（如目录列表、端口扫描、技术栈）。"""
            return result_cache.save_recon(code, category, data)

        @tool
        async def read_recon_cache(category: str | None = None) -> str:
            """读取侦察缓存。不指定category返回全部。"""
            return result_cache.get_recon(code, category)

        @tool
        async def search_vuln_kb(query: str) -> str:
            """搜索漏洞知识库。例如: 'sql injection', 'ssti', 'file upload', '命令注入', 'ssrf', 'jwt'"""
            return vuln_kb.search(query)

        @tool
        async def get_payloads(vuln_type: str) -> str:
            """获取指定漏洞类型的全部Payload列表。类型: sqli/xss/cmdi/lfi/upload/ssrf/ssti/deser/idor/jwt/xxe/infoleak/auth/cloud/privesc/lateral/cve_common/ai_infra"""
            return vuln_kb.get_payloads(vuln_type)

        @tool
        async def get_tool_commands(tool_name: str, target: str = "TARGET") -> str:
            """获取渗透工具命令模板。工具: nmap/ffuf/dirsearch/sqlmap/nuclei/curl"""
            return vuln_kb.get_tool_commands(tool_name, target)

        poc_idx = self.poc_index

        @tool
        async def search_poc_kb(query: str) -> str:
            """搜索外部POC知识库(含3000+漏洞POC文档)。支持CVE编号、产品名、厂商名、漏洞类型。例如: 'CVE-2021-44228', '用友NC', 'Fastjson', 'Confluence RCE'"""
            return poc_idx.search(query)

        @tool
        async def read_poc_file(filepath: str) -> str:
            """读取POC知识库中某个文件的完整内容(由search_poc_kb返回的路径)"""
            return poc_idx.read_file(filepath)

        agent_self = self

        @tool
        async def auto_recon(target_url: str) -> str:
            """对目标执行自动化深度侦察（JS分析+漏扫+泄露检测），返回结构化报告。一次调用即可完成完整侦察。"""
            sections = []
            sections.append(f"═══ 自动侦察报告: {target_url} ═══\n")

            js_result = await agent_self._run_bash(
                f"python3 scripts/exploits/js_analyzer.py {target_url}",
                timeout_seconds=60,
            )
            sections.append("── JS 深度分析 ──")
            sections.append(js_result)

            vuln_result = await agent_self._run_bash(
                f"python3 scripts/exploits/vuln_scanner.py {target_url} --json",
                timeout_seconds=60,
            )
            sections.append("\n── 漏洞扫描 ──")
            sections.append(vuln_result)

            header_result = await agent_self._run_bash(
                f"curl -sIL --connect-timeout 5 {target_url}",
                timeout_seconds=15,
            )
            sections.append("\n── 响应头 ──")
            sections.append(header_result)

            leak_paths = [
                "robots.txt", ".git/config", ".env", ".DS_Store",
                "swagger-ui.html", "v2/api-docs", "actuator", "actuator/env",
                "druid/index.html", "nacos/", "console",
            ]
            leak_found = []
            for path in leak_paths:
                check = await agent_self._run_bash(
                    f"curl -sL -o /dev/null -w '%{{http_code}}' --connect-timeout 3 {target_url.rstrip('/')}/{path}",
                    timeout_seconds=8,
                )
                try:
                    import json as _json
                    status = _json.loads(check).get("stdout", "").strip().strip("'")
                    if status in ("200", "301", "302", "403"):
                        leak_found.append(f"  [{status}] /{path}")
                except Exception:
                    pass

            if leak_found:
                sections.append("\n── 泄露/敏感路径 ──")
                sections.append("\n".join(leak_found))

            sections.append("\n═══ 侦察完成 ═══")
            return "\n".join(sections)

        # ── 预执行侦察：子智能体启动前自动收集基础信息 ──────────
        pre_recon_context = ""
        if entrypoint:
            ep_url = str(entrypoint)
            if not ep_url.startswith("http"):
                ep_url = "http://" + ep_url
            try:
                vuln_scan = await self._run_bash(
                    f"python3 scripts/exploits/vuln_scanner.py {ep_url} --json",
                    timeout_seconds=45,
                )
                js_scan = await self._run_bash(
                    f"python3 scripts/exploits/js_analyzer.py {ep_url}",
                    timeout_seconds=45,
                )
                pre_recon_parts = []
                if vuln_scan and "error" not in vuln_scan.lower()[:50]:
                    pre_recon_parts.append(f"[预执行漏扫结果]\n{vuln_scan[:3000]}")
                if js_scan and "error" not in js_scan.lower()[:50]:
                    pre_recon_parts.append(f"[预执行JS分析结果]\n{js_scan[:3000]}")
                if pre_recon_parts:
                    pre_recon_context = "\n\n".join(pre_recon_parts)
                    self._emit("system", f"[预执行侦察] {code}: 已收集 {len(pre_recon_parts)} 项基础信息")
            except Exception as exc:
                self._emit("system", f"[预执行侦察] {code}: 跳过 ({exc})")

        # ── 构建子智能体 ─────────────────────────────────────────

        previous_notes = notes.get_challenge_notes(code)
        previous_recon = result_cache.get_recon(code)

        context_parts: list[str] = []
        if previous_notes and "暂无" not in previous_notes:
            context_parts.append(f"历史笔记:\n{previous_notes}")
        if previous_recon and "无侦察" not in previous_recon:
            context_parts.append(f"侦察缓存:\n{previous_recon}")
        if pre_recon_context:
            context_parts.append(f"★预执行侦察结果(已自动收集):\n{pre_recon_context}")
        context_from_notes = "\n\n".join(context_parts) if context_parts else "无历史数据，需从零开始侦察。"

        child_system_prompt = CHILD_SYSTEM_TEMPLATE.format(
            base_system_prompt=SYSTEM_PROMPT,
            title=title,
            code=code,
            entrypoint=entrypoint,
            previous_notes=context_from_notes,
        )

        current_round = getattr(self, "_current_round", 1)
        if current_round <= 1:
            child_mission_prompt = CHILD_MISSION_FIRST_ROUND.format(
                title=title,
                code=code,
                entrypoint=entrypoint,
                context_from_notes=context_from_notes,
            )
        else:
            attempts = self.notes.get_attempts(code)
            if attempts:
                failed_lines = [f"  - [{a.get('ts', '')}] {a['method']} → {a['result']}" for a in attempts[-20:]]
                failed_attempts = "\n".join(failed_lines)
            else:
                failed_attempts = "暂无记录（但之前的笔记中可能包含已尝试信息）"
            child_mission_prompt = CHILD_MISSION_RETRY_ROUND.format(
                title=title,
                code=code,
                round_num=current_round,
                entrypoint=entrypoint,
                context_from_notes=context_from_notes,
                failed_attempts=failed_attempts,
            )

        child_agent = create_deep_agent(
            model=model,
            system_prompt=child_system_prompt,
            tools=[
                bash_tool,
                start_current_challenge,
                stop_current_challenge,
                view_current_hint,
                submit_current_flag,
                refresh_challenge_status,
                save_challenge_note,
                read_challenge_notes,
                save_recon_cache,
                read_recon_cache,
                search_vuln_kb,
                get_payloads,
                get_tool_commands,
                search_poc_kb,
                read_poc_file,
                auto_recon,
            ],
        )

        self._emit("system", f"[主智能体] 子智能体已分配: {title} ({code})")
        report = await self._run_streamed_deep_agent(child_agent, child_mission_prompt)

        try:
            await self._call_mcp("stop_challenge", {"code": code})
        except Exception as exc:  # noqa: BLE001
            self._emit("system", f"[主智能体] 赛题 {code} 停止实例失败（可忽略）: {exc}")

        return report

    async def _call_mcp(self, tool_name: str, arguments: dict[str, Any]) -> str:
        if self._mcp_session is None:
            raise RuntimeError("MCP session not initialized")

        self._emit("tool_call", f"调用工具: {tool_name}，参数: {json.dumps(arguments, ensure_ascii=False)}")

        call_key = f"{tool_name}:{json.dumps(arguments, ensure_ascii=False, sort_keys=True)}"
        count = self._tool_call_counters.get(call_key, 0) + 1
        self._tool_call_counters[call_key] = count
        if count > self._repeat_call_limit:
            repeated_msg = (
                f"检测到重复调用: {tool_name} 参数未变化，已连续 {count} 次。"
                "请停止重复调用，转向下一步分析或尝试其他工具。"
            )
            self._emit("tool_result", f"[{tool_name}] 结果: {repeated_msg}")
            return repeated_msg

        result = await call_tool(self._mcp_session, tool_name, arguments)

        if hasattr(result, "content") and isinstance(result.content, list):
            parts: list[str] = []
            for item in result.content:
                text = getattr(item, "text", None)
                if text:
                    parts.append(text)
                else:
                    parts.append(str(item))
            result_text = "\n".join(parts)
            self._emit("tool_result", f"[{tool_name}] 结果: {result_text[:500]}")
            return result_text

        result_text = str(result)
        self._emit("tool_result", f"[{tool_name}] 结果: {result_text[:500]}")
        return result_text

    def _render_bash_result(
        self,
        command: str,
        cwd: Path,
        timeout_seconds: int,
        completed_process: subprocess.CompletedProcess[str] | None,
        error: str | None = None,
    ) -> str:
        if error is not None:
            return json.dumps(
                {"command": command, "cwd": str(cwd), "timeout_seconds": timeout_seconds, "error": error},
                ensure_ascii=False, indent=2,
            )

        assert completed_process is not None
        stdout = completed_process.stdout or ""
        stderr = completed_process.stderr or ""
        if len(stdout) > self._bash_max_output_chars:
            stdout = stdout[: self._bash_max_output_chars] + "\n... [stdout truncated]"
        if len(stderr) > self._bash_max_output_chars:
            stderr = stderr[: self._bash_max_output_chars] + "\n... [stderr truncated]"

        return json.dumps(
            {
                "command": command, "cwd": str(cwd), "timeout_seconds": timeout_seconds,
                "returncode": completed_process.returncode, "stdout": stdout, "stderr": stderr,
            },
            ensure_ascii=False, indent=2,
        )

    async def _run_bash(self, command: str, cwd: str | None = None, timeout_seconds: int | None = None) -> str:
        workdir = Path(cwd).expanduser().resolve() if cwd else self._workspace_root
        timeout = timeout_seconds or self._bash_timeout_seconds

        if not workdir.exists():
            return self._render_bash_result(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"cwd 不存在: {workdir}",
            )

        def _execute() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-lc", command],
                cwd=str(workdir), capture_output=True, text=True, timeout=timeout,
            )

        try:
            completed_process = await asyncio.to_thread(_execute)
        except subprocess.TimeoutExpired:
            return self._render_bash_result(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"命令执行超时（>{timeout} 秒）",
            )
        except Exception as exc:  # noqa: BLE001
            return self._render_bash_result(
                command=command, cwd=workdir, timeout_seconds=timeout,
                completed_process=None, error=f"命令执行失败: {exc}",
            )

        return self._render_bash_result(
            command=command, cwd=workdir, timeout_seconds=timeout,
            completed_process=completed_process,
        )

    async def run_competition(self, mcp_session: ClientSession) -> AgentRunResult:
        logger.info("=== 开始 DeepAgents 闯关流程（并发模式） ===")
        self._mcp_session = mcp_session

        model = ChatOpenAI(
            model=self.config["MODEL_ID"],
            api_key=self.config["MODEL_API_KEY"],
            base_url=self.config["MODEL_BASE_URL"],
            temperature=0.2,
        )

        self._emit("system", f"模型已就绪: {self.model_name} ({self.config['MODEL_ID']})")
        self._emit(
            "system",
            f"DeepAgents 参数: timeout={self._timeout_seconds}s, "
            f"recursion_limit={self._recursion_limit}, "
            f"repeat_call_limit={self._repeat_call_limit}, "
            f"max_concurrent={self._max_concurrent}, "
            f"max_iterations={self.max_iterations}",
        )
        self._emit("user", MISSION_PROMPT)

        challenges_text = await self._call_mcp("list_challenges", {})
        challenges_data = self._try_parse_json(challenges_text) or {}
        challenges = challenges_data.get("challenges", [])
        if not isinstance(challenges, list):
            challenges = []

        unsolved: list[dict[str, Any]] = []
        for challenge in challenges:
            if not isinstance(challenge, dict):
                continue
            ch_code = str(challenge.get("code", ""))
            if self.notes.is_solved(ch_code):
                continue
            if challenge.get("flag_got_count", 0) < challenge.get("flag_count", 1):
                unsolved.append(challenge)

        if not unsolved:
            msg = "所有当前可见赛题已完成，无需继续执行。"
            self._emit("system", msg)
            return AgentRunResult(final_message=msg, iterations=0)

        self._emit("system", f"[主智能体] 待处理赛题数: {len(unsolved)}，并发上限: {self._max_concurrent}")

        max_rounds = int(self.config.get("DEEPAGENTS_MAX_RETRY_ROUNDS", "3"))
        results_map: dict[str, AgentRunResult | Exception] = {}
        self._current_round = 0
        total_iterations = 0

        for round_num in range(1, max_rounds + 1):
            self._current_round = round_num
            # 每轮只排除已确认 solved 的题目，未解的全部重试（带历史上下文）
            pending = [
                ch for ch in unsolved
                if not self.notes.is_solved(str(ch.get("code", "")))
            ]

            if not pending:
                self._emit("system", f"[第{round_num}轮] 所有题目已解决，提前结束")
                break

            is_retry = round_num > 1
            label = f"第{round_num}轮{'(续攻)' if is_retry else ''}"
            self._emit("system", f"[{label}] 待处理: {len(pending)} 题")

            sem = asyncio.Semaphore(self._max_concurrent)

            async def _run_with_semaphore(ch: dict[str, Any], _round: int = round_num) -> None:
                ch_code = str(ch.get("code", ""))
                ch_title = str(ch.get("title", ""))
                async with sem:
                    self._emit("system", f"[并发调度] 第{_round}轮开始: {ch_title} ({ch_code})")
                    try:
                        report = await self._run_single_challenge_agent(model, ch)
                        results_map[ch_code] = report
                    except Exception as exc:  # noqa: BLE001
                        self._emit("system", f"[并发调度] 子智能体异常: {ch_title} ({ch_code}): {exc}")
                        results_map[ch_code] = exc

            tasks = [_run_with_semaphore(ch) for ch in pending]
            await asyncio.gather(*tasks)

            # 本轮结束后刷新已解状态
            try:
                refresh_text = await self._call_mcp("list_challenges", {})
                refresh_data = self._try_parse_json(refresh_text) or {}
                for ch in refresh_data.get("challenges", []):
                    if isinstance(ch, dict):
                        ch_code = str(ch.get("code", ""))
                        if ch.get("flag_got_count", 0) >= ch.get("flag_count", 1):
                            self.notes.record_solved(ch_code, "platform_confirmed")
            except Exception:  # noqa: BLE001
                pass

            still_unsolved = [
                ch for ch in unsolved
                if not self.notes.is_solved(str(ch.get("code", "")))
            ]
            self._emit("system", f"[{label}] 本轮结束，剩余未解: {len(still_unsolved)} 题")

            if not still_unsolved:
                break

        # ── 汇总结果 ────────────────────────────────────────────
        summaries: list[str] = []

        for ch in unsolved:
            ch_code = str(ch.get("code", ""))
            ch_title = str(ch.get("title", ""))
            result = results_map.get(ch_code)

            if isinstance(result, AgentRunResult):
                total_iterations += result.iterations
                solved = self.notes.is_solved(ch_code)
                summaries.append(
                    f"- {ch_title} ({ch_code}): {'已完成' if solved else '未完成'} | "
                    f"子智能体总结: {result.final_message[:200] or '(无输出)'}"
                )
            elif isinstance(result, Exception):
                summaries.append(f"- {ch_title} ({ch_code}): 异常 | {result}")
            else:
                summaries.append(f"- {ch_title} ({ch_code}): 未执行")

        # 最终确认状态
        try:
            final_status_text = await self._call_mcp("list_challenges", {})
            final_status = self._try_parse_json(final_status_text) or {}
            solved_count = final_status.get("solved_challenges", "?")
            total_count = final_status.get("total_challenges", "?")
            summaries.append(f"\n平台确认: 已完成 {solved_count}/{total_count} 道赛题")
        except Exception:  # noqa: BLE001
            pass

        final_message = "主从并发模式执行完成。各子智能体结果:\n" + "\n".join(summaries)
        self._emit("assistant", final_message)
        return AgentRunResult(final_message=final_message, iterations=total_iterations)
