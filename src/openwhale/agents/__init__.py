"""智能体基座与实现。"""

from .base import AgentRunResult, AgentToolCall, BaseChallengeAgent
from .deepagents_agent import DeepAgentsChallengeAgent
from .factory import create_agent
from .openai_agent import OpenAIChallengeAgent
from .prompts import MISSION_PROMPT, SYSTEM_PROMPT
from .strategy_agent import ChallengeState, StrategyMasterAgent

try:
    from .claude_code_agent import ClaudeCodeChallengeAgent
except ImportError:
    ClaudeCodeChallengeAgent = None  # type: ignore[assignment,misc]

__all__ = [
    "AgentRunResult",
    "AgentToolCall",
    "BaseChallengeAgent",
    "ChallengeState",
    "ClaudeCodeChallengeAgent",
    "DeepAgentsChallengeAgent",
    "OpenAIChallengeAgent",
    "MISSION_PROMPT",
    "SYSTEM_PROMPT",
    "StrategyMasterAgent",
    "create_agent",
]