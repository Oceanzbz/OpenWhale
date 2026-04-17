"""持久化笔记系统 - 跨运行保存渗透发现与上下文。"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


class PentestNotes:
    """基于 JSON 文件的持久化笔记系统，支持跨运行复用发现。"""

    def __init__(self, path: str | Path = "pentest_notes.json"):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"challenges": {}, "global": {}, "solved_flags": {}}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ── 赛题笔记 ────────────────────────────────────────────────

    def save_challenge_note(
        self, code: str, category: str, content: str
    ) -> str:
        """保存赛题笔记。category 建议: recon / vuln / exploit / credential / path / param / error"""
        with self._lock:
            ch = self._data.setdefault("challenges", {}).setdefault(code, {})
            notes = ch.setdefault(category, [])
            notes.append(
                {"content": content, "ts": datetime.now().isoformat()}
            )
            self._save()
        return f"已保存 [{category}] → 赛题 {code}"

    def get_challenge_notes(self, code: str) -> str:
        """获取某道赛题的全部笔记（可供子智能体启动时加载上下文）。"""
        with self._lock:
            ch = self._data.get("challenges", {}).get(code, {})
        if not ch:
            return f"赛题 {code} 暂无历史笔记。"
        parts: list[str] = [f"=== 赛题 {code} 历史笔记 ==="]
        for cat, notes in ch.items():
            parts.append(f"\n## {cat}")
            for n in notes:
                parts.append(f"  - [{n.get('ts','')}] {n.get('content', str(n))}")
        return "\n".join(parts)

    def get_all_notes_summary(self) -> str:
        """获取所有赛题的笔记摘要。"""
        with self._lock:
            challenges = self._data.get("challenges", {})
        if not challenges:
            return "暂无任何笔记。"
        parts: list[str] = []
        for code, cats in challenges.items():
            total = sum(len(v) for v in cats.values())
            parts.append(f"赛题 {code}: {total} 条笔记, 类别: {list(cats.keys())}")
        return "\n".join(parts)

    # ── 全局笔记 ────────────────────────────────────────────────

    def save_global_note(self, key: str, content: str) -> str:
        """保存全局笔记（环境信息、通用发现等）。"""
        with self._lock:
            g = self._data.setdefault("global", {})
            g.setdefault(key, []).append(
                {"content": content, "ts": datetime.now().isoformat()}
            )
            self._save()
        return f"已保存全局笔记 [{key}]"

    def get_global_notes(self) -> str:
        with self._lock:
            g = self._data.get("global", {})
        if not g:
            return "暂无全局笔记。"
        parts: list[str] = ["=== 全局笔记 ==="]
        for key, entries in g.items():
            parts.append(f"\n## {key}")
            for e in entries:
                parts.append(f"  - [{e.get('ts','')}] {e.get('content', str(e))}")
        return "\n".join(parts)

    # ── Flag 记录 ───────────────────────────────────────────────

    def record_solved(self, code: str, flag: str) -> None:
        with self._lock:
            self._data.setdefault("solved_flags", {})[code] = {
                "flag": flag,
                "ts": datetime.now().isoformat(),
            }
            self._save()

    def is_solved(self, code: str) -> bool:
        with self._lock:
            return code in self._data.get("solved_flags", {})

    def clear_solved(self, code: str) -> None:
        """清除本地 solved 记录（用于平台数据校准）。"""
        with self._lock:
            if code in self._data.get("solved_flags", {}):
                del self._data["solved_flags"][code]
                self._save()

    def get_solved_codes(self) -> set[str]:
        with self._lock:
            return set(self._data.get("solved_flags", {}).keys())

    # ── 已尝试 exploit 去重 ─────────────────────────────────────

    def record_attempt(self, code: str, method: str, result: str) -> str:
        """记录一次利用尝试，方便后续跳过已失败的方法。"""
        with self._lock:
            ch = self._data.setdefault("challenges", {}).setdefault(code, {})
            attempts = ch.setdefault("_attempts", [])
            attempts.append(
                {"method": method, "result": result, "ts": datetime.now().isoformat()}
            )
            self._save()
        return f"已记录尝试: {method} → {result}"

    def get_attempts(self, code: str) -> list[dict[str, str]]:
        with self._lock:
            ch = self._data.get("challenges", {}).get(code, {})
            return list(ch.get("_attempts", []))


class GlobalIntel:
    """Cross-challenge intelligence sharing layer.

    Stores credentials, tech stacks, working exploits, and common patterns
    discovered across all challenges so the strategy agent can route info
    to relevant sub-agents.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._credentials: list[dict[str, str]] = []
        self._tech_stacks: dict[str, list[str]] = {}
        self._working_exploits: list[dict[str, str]] = []
        self._patterns: list[str] = []

    # ── Credentials ──────────────────────────────────────────────

    def record_credential(self, source_code: str, username: str, password: str) -> None:
        with self._lock:
            self._credentials.append({
                "source": source_code,
                "username": username,
                "password": password,
                "ts": datetime.now().isoformat(),
            })

    def get_credentials(self) -> list[dict[str, str]]:
        with self._lock:
            return list(self._credentials)

    # ── Tech Stack ───────────────────────────────────────────────

    def record_tech_stack(self, challenge_code: str, tech: list[str]) -> None:
        with self._lock:
            self._tech_stacks[challenge_code] = tech

    def get_tech_stack(self, challenge_code: str) -> list[str]:
        with self._lock:
            return list(self._tech_stacks.get(challenge_code, []))

    def find_challenges_by_tech(self, keyword: str) -> list[str]:
        """Find challenge codes whose tech stack matches a keyword."""
        kw = keyword.lower()
        with self._lock:
            return [
                code for code, techs in self._tech_stacks.items()
                if any(kw in t.lower() for t in techs)
            ]

    # ── Working Exploits ─────────────────────────────────────────

    def record_working_exploit(self, code: str, method: str, detail: str) -> None:
        with self._lock:
            self._working_exploits.append({
                "code": code,
                "method": method,
                "detail": detail[:200],
                "ts": datetime.now().isoformat(),
            })

    def get_working_exploits(self) -> list[dict[str, str]]:
        with self._lock:
            return list(self._working_exploits)

    # ── Common Patterns ──────────────────────────────────────────

    def record_pattern(self, pattern: str) -> None:
        with self._lock:
            if pattern not in self._patterns:
                self._patterns.append(pattern)

    # ── Brief summary for injection into prompts ─────────────────

    def get_brief(self) -> str:
        """Return a concise summary suitable for injecting into agent context."""
        parts: list[str] = []
        with self._lock:
            if self._credentials:
                creds = [f"{c['username']}:{c['password']}(来源{c['source']})" for c in self._credentials[-5:]]
                parts.append(f"已发现凭据: {', '.join(creds)}")
            if self._working_exploits:
                exps = [f"{e['code']}:{e['method']}" for e in self._working_exploits[-5:]]
                parts.append(f"已成功方法: {', '.join(exps)}")
            if self._patterns:
                parts.append(f"共性模式: {'; '.join(self._patterns[-3:])}")
        return "\n".join(parts)
