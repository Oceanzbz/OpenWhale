"""智能体工厂 - 根据配置创建智能体实例，注入共享的笔记/缓存/知识库。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..util.cache import ResultCache
from ..util.notes import PentestNotes
from ..util.poc_index import PocIndex
from ..util.vuln_kb import VulnKnowledgeBase
from .deepagents_agent import DeepAgentsChallengeAgent
from .openai_agent import OpenAIChallengeAgent


def _init_shared_utils(config: dict[str, str]) -> tuple[PentestNotes, ResultCache, VulnKnowledgeBase, PocIndex]:
    """初始化共享的笔记/缓存/知识库/POC索引实例。"""
    data_dir = Path(config.get("DATA_DIR", "data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    notes = PentestNotes(path=data_dir / "pentest_notes.json")
    cache = ResultCache(path=data_dir / "pentest_cache.json")
    vuln_kb = VulnKnowledgeBase()
    poc_index = PocIndex(cache_path=data_dir / "poc_index_cache.json")
    return notes, cache, vuln_kb, poc_index


def create_agent(config: dict[str, str], on_message: Callable[[str, str], None] | None = None):
    """根据配置创建智能体实例。"""
    backend = config.get("AGENT_BACKEND", "openai_compat").lower()
    notes, cache, vuln_kb, poc_index = _init_shared_utils(config)

    if backend in {"openai", "openai_compat", "minimax", "chat_completions"}:
        return OpenAIChallengeAgent(
            api_key=config["MODEL_API_KEY"],
            base_url=config["MODEL_BASE_URL"],
            model=config["MODEL_ID"],
            model_name=config["MODEL_NAME"],
            on_message=on_message,
            notes=notes,
            cache=cache,
            vuln_kb=vuln_kb,
            poc_index=poc_index,
        )

    if backend in {"claude", "claude_code", "claude_sdk", "claude-agent-sdk"}:
        from .claude_code_agent import ClaudeCodeChallengeAgent
        return ClaudeCodeChallengeAgent(
            config=config,
            on_message=on_message,
            notes=notes,
            cache=cache,
            vuln_kb=vuln_kb,
            poc_index=poc_index,
        )

    if backend == "deepagents":
        return DeepAgentsChallengeAgent(
            config=config,
            on_message=on_message,
            notes=notes,
            cache=cache,
            vuln_kb=vuln_kb,
            poc_index=poc_index,
        )

    raise NotImplementedError(
        "暂不支持的智能体基座: "
        f"{backend}. 目前可用: openai_compat/minimax/openai/chat_completions/claude_code/deepagents"
    )
