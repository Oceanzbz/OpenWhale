"""技能发现与加载器。

设计原则（借鉴 Claude Code Skills 机制）：
- 技能是 Markdown 文件，存放在 skills/ 目录下
- 按类别分目录：core/ methodology/ tools/ vulnerabilities/
- 支持按名称、按标签、按阶段加载
- 结果有缓存，同一技能只读一次磁盘
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Sequence

import logging

logger = logging.getLogger(__name__)

_SKILLS_DIR = Path(__file__).parent


PHASE_SKILL_MAP: dict[str, list[str]] = {
    "recon": [
        "core/identity",
        "core/rules",
        "core/available_tools",
        "methodology/recon",
    ],
    "exploit": [
        "core/identity",
        "core/rules",
        "core/available_tools",
        "methodology/exploit",
        "methodology/ctf_bypass",
        "vulnerabilities/advanced_exploit",
    ],
    "deep_dive": [
        "core/identity",
        "core/rules",
        "core/available_tools",
        "methodology/exploit",
        "methodology/ctf_bypass",
        "vulnerabilities/cve_patterns",
        "vulnerabilities/advanced_exploit",
    ],
    "full": [
        "core/identity",
        "core/rules",
        "core/available_tools",
        "methodology/recon",
        "methodology/exploit",
        "methodology/ctf_bypass",
        "vulnerabilities/owasp_top10",
        "vulnerabilities/cve_patterns",
        "vulnerabilities/advanced_exploit",
    ],
    "easy_recon": [
        "core/identity",
        "core/rules",
    ],
    "easy_exploit": [
        "core/identity",
        "core/rules",
        "methodology/exploit",
    ],
}


class SkillLoader:
    """技能加载器，支持按名称和按阶段批量加载。"""

    def __init__(self, skills_dir: Path | None = None) -> None:
        self._dir = skills_dir or _SKILLS_DIR
        self._cache: dict[str, str] = {}

    def load(self, skill_name: str) -> str:
        """加载单个技能文件，返回 Markdown 文本。skill_name 如 'core/identity'。"""
        if skill_name in self._cache:
            return self._cache[skill_name]

        path = self._dir / f"{skill_name}.md"
        if not path.is_file():
            logger.warning(f"技能文件不存在: {path}")
            return ""

        content = path.read_text(encoding="utf-8").strip()
        self._cache[skill_name] = content
        return content

    def load_many(self, skill_names: Sequence[str]) -> list[str]:
        """批量加载多个技能，返回非空内容列表。"""
        sections = []
        for name in skill_names:
            content = self.load(name)
            if content:
                sections.append(content)
        return sections

    def load_for_phase(self, phase: str) -> list[str]:
        """根据阶段名称加载预定义的技能集合。

        phase: 'recon' | 'exploit' | 'deep_dive' | 'full'
        """
        skill_names = PHASE_SKILL_MAP.get(phase, PHASE_SKILL_MAP["full"])
        return self.load_many(skill_names)

    def build_prompt_section(self, phase: str) -> str:
        """加载阶段技能并拼接为单个 prompt section 字符串。"""
        sections = self.load_for_phase(phase)
        return "\n\n".join(sections)

    def get_available_skills(self) -> list[str]:
        """列出所有可用技能名称。"""
        skills = []
        for path in sorted(self._dir.rglob("*.md")):
            relative = path.relative_to(self._dir)
            skill_name = str(relative.with_suffix(""))
            skills.append(skill_name)
        return skills

    def estimate_tokens(self, phase: str) -> int:
        """粗略估算某阶段技能的 token 数（中文约 1.5 token/字）。"""
        text = self.build_prompt_section(phase)
        return int(len(text) * 1.5)

    def clear_cache(self) -> None:
        """清除缓存，强制下次从磁盘重新加载。"""
        self._cache.clear()


@lru_cache(maxsize=1)
def get_default_loader() -> SkillLoader:
    """获取全局默认的 SkillLoader 实例。"""
    return SkillLoader()
