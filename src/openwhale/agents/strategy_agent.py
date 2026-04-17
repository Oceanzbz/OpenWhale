"""LLM-driven Strategy Master Agent.

v2 改进：
- _get_phase_budget 与 DIFFICULTY_BUDGETS 对齐
- JSON解析增强：支持更多格式容错
- fallback_decisions 增强：easy题不进deep_dive
- _build_state_summary 增加题目描述
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

from langchain_openai import ChatOpenAI
from loguru import logger

from ..util.notes import GlobalIntel, PentestNotes


@dataclass
class ChallengeState:
    """Tracks a single challenge through the phased pipeline."""

    code: str
    title: str
    difficulty: str
    score: int
    description: str = ""
    phase: str = "pending"
    budget_steps: int = 0
    budget_time: int = 0
    tech_stack: list[str] = field(default_factory=list)
    attack_vectors_tried: list[str] = field(default_factory=list)
    attack_vectors_remaining: list[str] = field(default_factory=list)
    key_findings: list[str] = field(default_factory=list)
    recon_report: str | None = None
    steps_used: int = 0
    time_used: float = 0.0

    @property
    def roi_score(self) -> float:
        success_rate = {"easy": 0.8, "medium": 0.5, "hard": 0.2}.get(self.difficulty, 0.5)
        est_time = {"easy": 5, "medium": 10, "hard": 20}.get(self.difficulty, 10)
        return (success_rate * self.score) / est_time


STRATEGY_SYSTEM_PROMPT = """\
你是 OpenWhale 渗透测试团队的 **策略主官 (Team Lead)**。
你的职责是决策，不是执行。你不需要写任何 exploit，只需要基于下属汇报的信息做出调度决定。

当前比赛状态会以 JSON 提供给你，你需要返回下一步调度指令。

决策原则：
1. ★ 难度优先 — 必须优先调度所有 easy 题，其次 medium，最后 hard
2. ★ EASY题简单处理 — easy题应该快速通过，不要分配复杂的攻击方向
3. ROI 优先 — 同难度内按分数/预估时间排序
4. 谨慎放弃 — 只有在3个阶段都无进展时才标记 abandoned
5. 情报复用 — 如果A题发现的凭据/技术栈对B题有用，指示B题优先尝试
6. 预算适度 — easy 题预算 7min，medium 21min，hard 45min
7. 注意题目描述 — 有些题的描述本身就是提示(如MD5 hash、关键词)，要充分利用

★ 你必须对每道未解题目都给出决策，不要遗漏任何一道。

你的输出必须是严格的 JSON 格式（不要包含 markdown 代码块标记）:
{
  "decisions": [
    {
      "code": "challenge_code",
      "action": "start_recon | start_exploit | start_deep_dive | redirect",
      "attack_directions": ["方向1", "方向2"],
      "reason": "简短决策理由"
    }
  ],
  "intel_broadcast": "需要广播给所有子Agent的跨题情报（可选，无则空字符串）"
}

注意：不要使用 abandon，每道题都必须有行动。
"""


class StrategyMasterAgent:
    """Lightweight LLM-based decision maker for challenge orchestration."""

    def __init__(
        self,
        model: ChatOpenAI,
        notes: PentestNotes,
        intel: GlobalIntel,
        emit_fn=None,
    ) -> None:
        self.model = model
        self.notes = notes
        self.intel = intel
        self._emit = emit_fn or (lambda role, content: None)
        self.states: dict[str, ChallengeState] = {}

    def init_states(self, challenges: list[dict[str, Any]]) -> None:
        for ch in challenges:
            code = str(ch.get("code", ""))
            self.states[code] = ChallengeState(
                code=code,
                title=str(ch.get("title", "")),
                difficulty=str(ch.get("difficulty", "medium")).lower(),
                score=int(ch.get("total_score", 0) or ch.get("score", 0) or 0),
                description=str(ch.get("description", "")),
            )

    def mark_phase(self, code: str, phase: str) -> None:
        if code in self.states:
            self.states[code].phase = phase

    def record_recon_findings(self, code: str, report: str, tech: list[str] | None = None) -> None:
        if code not in self.states:
            return
        st = self.states[code]
        st.recon_report = report[:4000]
        if tech:
            st.tech_stack = tech
            self.intel.record_tech_stack(code, tech)

    def record_key_finding(self, code: str, finding: str) -> None:
        if code in self.states:
            self.states[code].key_findings.append(finding)

    def record_steps(self, code: str, steps: int, time_s: float) -> None:
        if code in self.states:
            self.states[code].steps_used += steps
            self.states[code].time_used += time_s

    def get_priority_queue(self) -> list[ChallengeState]:
        active = [
            s for s in self.states.values()
            if s.phase not in ("solved", "abandoned")
        ]
        return sorted(active, key=lambda s: s.roi_score, reverse=True)

    async def decide_next_actions(
        self,
        batch_size: int = 3,
        extra_context: str = "",
    ) -> list[dict[str, Any]]:
        state_summary = self._build_state_summary()
        intel_brief = self.intel.get_brief()

        user_prompt = (
            f"当前比赛状态:\n{state_summary}\n\n"
            f"跨题情报:\n{intel_brief or '暂无'}\n\n"
            f"并发槽位: {batch_size}\n"
        )
        if extra_context:
            user_prompt += f"\n附加信息:\n{extra_context}\n"
        user_prompt += (
            f"\n请给出所有 {len(self.states)} 道题的调度决策。"
            f"每道题都必须有一条决策，不要遗漏。并发执行上限 {batch_size} 道（调度器自动控制）。"
        )

        self._emit("system", f"[策略主Agent] 请求LLM决策，{len(self.states)}题在管")
        try:
            response = await asyncio.wait_for(
                self.model.ainvoke([
                    {"role": "system", "content": STRATEGY_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ]),
                timeout=60,
            )
            raw = response.content if hasattr(response, "content") else str(response)
            data = self._parse_json_response(raw)
        except (TimeoutError, asyncio.TimeoutError):
            logger.warning("[策略主Agent] LLM决策超时(60s)，回退到启发式")
            self._emit("system", "[策略主Agent] LLM超时，使用启发式决策")
            return self._fallback_decisions(batch_size)
        except Exception as exc:
            logger.warning(f"[策略主Agent] LLM决策解析失败: {exc}，回退到启发式")
            return self._fallback_decisions(batch_size)

        decisions = data.get("decisions", [])
        if not isinstance(decisions, list):
            logger.warning("[策略主Agent] decisions不是列表，回退到启发式")
            return self._fallback_decisions(batch_size)

        broadcast = data.get("intel_broadcast", "")
        if broadcast:
            self.intel.record_pattern(broadcast)
            self._emit("system", f"[策略主Agent] 情报广播: {broadcast}")

        return decisions

    @staticmethod
    def _parse_json_response(raw: str) -> dict[str, Any]:
        """增强JSON解析，支持markdown代码块、多余文字等。"""
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        json_match = re.search(r'\{[\s\S]*"decisions"[\s\S]*\}', raw)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        raise ValueError(f"无法解析JSON: {raw[:200]}")

    async def checkpoint(
        self,
        code: str,
        step_count: int,
        progress_summary: str,
    ) -> str:
        st = self.states.get(code)
        if not st:
            return "continue"

        st.steps_used = step_count
        if self.notes.is_solved(code):
            st.phase = "solved"
            return "abort"

        budget = _get_phase_budget(st.difficulty, st.phase)
        if budget and step_count >= budget:
            self._emit("system", f"[策略主Agent] {code} 步数 {step_count} 达到阶段预算 {budget}，终止")
            return "abort"

        return "continue"

    def _build_state_summary(self) -> str:
        rows: list[str] = []
        for s in self.states.values():
            desc_preview = s.description[:60] + "..." if len(s.description) > 60 else s.description
            rows.append(
                f"  {s.code}: {s.title} | {s.difficulty} | {s.score}分 | "
                f"阶段={s.phase} | 已用步数={s.steps_used} | "
                f"发现={len(s.key_findings)} | "
                f"技术栈={','.join(s.tech_stack) or '未知'} | "
                f"描述={desc_preview or '无'}"
            )
        return "\n".join(rows)

    def _fallback_decisions(self, batch_size: int) -> list[dict[str, Any]]:
        queue = self.get_priority_queue()
        diff_order = {"easy": 0, "medium": 1, "hard": 2}
        queue.sort(key=lambda s: (diff_order.get(s.difficulty, 1), -s.roi_score))
        decisions: list[dict[str, Any]] = []
        for st in queue[:batch_size]:
            if st.phase in ("pending", "abandoned"):
                decisions.append({
                    "code": st.code,
                    "action": "start_recon",
                    "reason": f"启发式: {st.difficulty}题开始侦察",
                })
            elif st.phase == "recon":
                decisions.append({
                    "code": st.code,
                    "action": "start_exploit",
                    "attack_directions": [],
                    "reason": "启发式: 侦察完成，开始利用",
                })
            elif st.phase in ("exploit", "deep_dive"):
                decisions.append({
                    "code": st.code,
                    "action": "start_exploit",
                    "reason": f"启发式: {st.difficulty}题继续攻击（换方向）",
                })
        return decisions


def _get_phase_budget(difficulty: str, phase: str) -> int | None:
    """与 DIFFICULTY_BUDGETS 对齐的步数预算。"""
    budgets = {
        "easy":   {"recon": 25, "exploit": 60, "deep_dive": 0},
        "medium": {"recon": 35, "exploit": 80, "deep_dive": 50},
        "hard":   {"recon": 45, "exploit": 100, "deep_dive": 80},
    }
    return budgets.get(difficulty, budgets["medium"]).get(phase)
