"""Prompt 管理系统 - 分层拼装、按需组合、可审计。

借鉴 Claude Code 的设计理念：
- Prompt 不是一段固定字符串，而是一套分层拼装的 prompt runtime
- 分为：常驻身份 / 阶段技能 / 运行时上下文 / 任务指令
- 每个 section 独立可缓存、可插拔、可统计 token
"""

from .builder import PromptBuilder

__all__ = ["PromptBuilder"]
