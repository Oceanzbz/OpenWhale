"""结果缓存系统 - 持久化侦察结果，避免跨运行重复工作。"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


class ResultCache:
    """基于 JSON 文件的侦察/利用结果缓存。"""

    def __init__(self, path: str | Path = "pentest_cache.json"):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"entries": {}, "recon": {}}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    # ── 通用缓存 ────────────────────────────────────────────────

    def get(self, code: str, action: str, params: str = "") -> str | None:
        key = self._hash(f"{code}:{action}:{params}")
        with self._lock:
            entry = self._data.get("entries", {}).get(key)
        return entry.get("result") if entry else None

    def put(self, code: str, action: str, result: str, params: str = "") -> None:
        key = self._hash(f"{code}:{action}:{params}")
        with self._lock:
            self._data.setdefault("entries", {})[key] = {
                "code": code,
                "action": action,
                "params": params,
                "result": result[:4000],
                "ts": datetime.now().isoformat(),
            }
            self._save()

    # ── 侦察结果缓存 ────────────────────────────────────────────

    def save_recon(self, code: str, category: str, data: Any) -> str:
        """缓存侦察结果（如目录扫描、端口扫描、技术栈识别等）。"""
        with self._lock:
            recon = self._data.setdefault("recon", {}).setdefault(code, {})
            recon[category] = {
                "data": data if isinstance(data, str) else json.dumps(data, ensure_ascii=False),
                "ts": datetime.now().isoformat(),
            }
            self._save()
        return f"已缓存侦察结果 [{category}] → 赛题 {code}"

    def get_recon(self, code: str, category: str | None = None) -> str:
        """获取侦察缓存。不指定 category 则返回全部。"""
        with self._lock:
            recon = self._data.get("recon", {}).get(code, {})
        if not recon:
            return f"赛题 {code} 无侦察缓存。"
        if category:
            entry = recon.get(category)
            if not entry:
                return f"赛题 {code} 无 [{category}] 侦察缓存。"
            return f"[{category}] ({entry['ts']}):\n{entry['data']}"

        parts: list[str] = [f"=== 赛题 {code} 侦察缓存 ==="]
        for cat, entry in recon.items():
            data_preview = str(entry["data"])[:500]
            parts.append(f"\n## {cat} ({entry['ts']})\n{data_preview}")
        return "\n".join(parts)

    def get_all_recon_summary(self) -> str:
        """获取所有赛题的侦察缓存摘要。"""
        with self._lock:
            recon = self._data.get("recon", {})
        if not recon:
            return "暂无侦察缓存。"
        parts: list[str] = []
        for code, cats in recon.items():
            parts.append(f"赛题 {code}: 缓存类别 {list(cats.keys())}")
        return "\n".join(parts)

    # ── 已尝试命令去重 ──────────────────────────────────────────

    def was_command_tried(self, code: str, command_hash: str) -> bool:
        key = f"cmd:{code}:{command_hash}"
        with self._lock:
            return key in self._data.get("entries", {})

    def mark_command_tried(self, code: str, command: str, result_summary: str) -> None:
        key = f"cmd:{code}:{self._hash(command)}"
        with self._lock:
            self._data.setdefault("entries", {})[key] = {
                "code": code,
                "command": command[:500],
                "result_summary": result_summary[:1000],
                "ts": datetime.now().isoformat(),
            }
            self._save()
