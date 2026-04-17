"""Skills 系统 - 按需加载 Markdown 技能文件，减少 prompt 上下文占用。

借鉴 Claude Code 的设计：技能不是写死在 system prompt 里的长文本，
而是按阶段/场景动态注入的独立文档。
"""

from .loader import SkillLoader

__all__ = ["SkillLoader"]
