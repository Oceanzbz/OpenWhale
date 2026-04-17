"""上下文管理器 - 对话历史压缩与 token 控制。

借鉴 Claude Code 的设计：
- Auto-compact：当对话 token 数接近窗口上限时自动压缩
- 熔断机制：连续压缩失败时停止尝试
- 状态重注入：压缩后保留关键工具结果和发现
"""

from __future__ import annotations

import json
from typing import Any

import logging

logger = logging.getLogger(__name__)


DEFAULT_CONTEXT_WINDOW = 128_000
COMPACT_THRESHOLD_RATIO = 0.75
MAX_CONSECUTIVE_FAILURES = 3
RESERVED_FOR_SUMMARY = 4_000


def estimate_tokens(text: str) -> int:
    """粗略估算 token 数。中文约 1.5 token/字，英文约 0.25 token/word。"""
    if not text:
        return 0
    cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    other_chars = len(text) - cn_chars
    return int(cn_chars * 1.5 + other_chars * 0.4)


def estimate_messages_tokens(messages: list[dict[str, Any]]) -> int:
    """估算消息列表的总 token 数。"""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    total += estimate_tokens(str(part.get("text", "")))
                else:
                    total += estimate_tokens(str(part))
        tool_calls = msg.get("tool_calls", [])
        for tc in tool_calls:
            if isinstance(tc, dict):
                fn = tc.get("function", {})
                total += estimate_tokens(fn.get("name", ""))
                total += estimate_tokens(fn.get("arguments", ""))
    return total


class ContextManager:
    """管理对话历史的 token 占用，在接近上限时自动压缩。"""

    def __init__(
        self,
        context_window: int = DEFAULT_CONTEXT_WINDOW,
        compact_threshold: float = COMPACT_THRESHOLD_RATIO,
    ) -> None:
        self._context_window = context_window
        self._threshold = int(context_window * compact_threshold)
        self._consecutive_failures = 0

    def should_compact(self, messages: list[dict[str, Any]]) -> bool:
        """判断是否需要压缩。"""
        if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            return False
        current_tokens = estimate_messages_tokens(messages)
        return current_tokens > self._threshold

    def compact(
        self,
        messages: list[dict[str, Any]],
        *,
        keep_system: bool = True,
        keep_last_n: int = 6,
        max_summary_chars: int = 4000,
    ) -> list[dict[str, Any]]:
        """压缩对话历史。

        策略（借鉴 Claude Code 的 compact 机制）：
        1. 保留 system prompt（第一条消息）
        2. 将中间消息压缩为摘要
        3. 保留最近 N 条消息
        4. 重注入关键发现（flag、凭据、漏洞确认）

        Args:
            messages: 完整消息列表
            keep_system: 是否保留 system 消息
            keep_last_n: 保留最近几条消息
            max_summary_chars: 摘要最大字符数
        """
        if len(messages) <= keep_last_n + 2:
            return messages

        try:
            result = self._do_compact(messages, keep_system, keep_last_n, max_summary_chars)
            self._consecutive_failures = 0
            return result
        except Exception as exc:
            logger.warning(f"上下文压缩失败: {exc}")
            self._consecutive_failures += 1
            return messages

    def _do_compact(
        self,
        messages: list[dict[str, Any]],
        keep_system: bool,
        keep_last_n: int,
        max_summary_chars: int,
    ) -> list[dict[str, Any]]:
        compacted: list[dict[str, Any]] = []

        start_idx = 0
        if keep_system and messages and messages[0].get("role") == "system":
            compacted.append(messages[0])
            start_idx = 1

        middle = messages[start_idx:-keep_last_n] if keep_last_n > 0 else messages[start_idx:]
        tail = messages[-keep_last_n:] if keep_last_n > 0 else []

        key_findings = self._extract_key_findings(middle)
        summary = self._summarize_messages(middle, max_summary_chars)

        compacted.append({
            "role": "user",
            "content": (
                f"[上下文已压缩 - 原始 {len(middle)} 条消息]\n\n"
                f"## 对话摘要\n{summary}\n\n"
                + (f"## 关键发现\n{chr(10).join(key_findings)}\n\n" if key_findings else "")
                + "请基于以上摘要和下方最近的消息继续工作。"
            ),
        })

        compacted.extend(tail)

        before_tokens = estimate_messages_tokens(messages)
        after_tokens = estimate_messages_tokens(compacted)
        logger.info(
            f"上下文压缩: {len(messages)} → {len(compacted)} 条消息, "
            f"~{before_tokens} → ~{after_tokens} tokens ({(1 - after_tokens/max(before_tokens, 1))*100:.0f}% 减少)"
        )

        return compacted

    def _extract_key_findings(self, messages: list[dict[str, Any]]) -> list[str]:
        """从消息中提取关键发现（flag、凭据、确认的漏洞）。"""
        findings: list[str] = []
        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue

            if "flag{" in content:
                import re
                for flag in re.findall(r"flag\{[^}]+\}", content):
                    findings.append(f"发现 flag: {flag}")

            for keyword in ["答案正确", "correct", "登录成功", "shell", "webshell"]:
                if keyword in content.lower():
                    findings.append(f"关键事件: {content[:200]}")
                    break

        return findings[:20]

    def _summarize_messages(self, messages: list[dict[str, Any]], max_chars: int) -> str:
        """生成消息摘要（无 LLM，基于规则）。"""
        parts: list[str] = []
        total_len = 0

        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if not isinstance(content, str) or not content.strip():
                continue

            if role == "assistant":
                line = f"- [AI] {content[:300]}"
            elif role == "tool":
                tool_id = msg.get("tool_call_id", "")
                line = f"- [工具结果] {content[:200]}"
            elif role == "user":
                line = f"- [用户/系统] {content[:200]}"
            else:
                line = f"- [{role}] {content[:150]}"

            if total_len + len(line) > max_chars:
                parts.append("... (更早的消息已省略)")
                break
            parts.append(line)
            total_len += len(line)

        return "\n".join(parts)

    def get_stats(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """获取当前上下文统计信息。"""
        current_tokens = estimate_messages_tokens(messages)
        return {
            "message_count": len(messages),
            "estimated_tokens": current_tokens,
            "context_window": self._context_window,
            "threshold": self._threshold,
            "usage_ratio": current_tokens / self._context_window,
            "should_compact": self.should_compact(messages),
        }
