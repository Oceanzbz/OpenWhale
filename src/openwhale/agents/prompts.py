"""智能体提示词 - 向后兼容层。

原有设计：所有 prompt 都是巨型字符串常量，每个子 Agent 都复制完整 SYSTEM_PROMPT。
新设计：prompt 由 PromptBuilder + SkillLoader 按需组装，大幅减少上下文占用。

此文件保留旧常量名以兼容现有代码，但实际内容已大幅精简。
具体的方法论/工具/漏洞知识已移至 skills/ 目录下的 Markdown 文件。
"""

from __future__ import annotations

from ..prompts.builder import PromptBuilder

_builder = PromptBuilder()

SYSTEM_PROMPT = _builder.build_system_prompt(phase="full")

MISSION_PROMPT = _builder.build_mission_prompt()

# 旧模板保留函数形式，不再使用 .format() 注入完整 SYSTEM_PROMPT
# 子 Agent 现在通过 PromptBuilder.build_child_system_prompt() 按阶段组装

CHILD_SYSTEM_TEMPLATE = (
    "{base_system_prompt}\n\n"
    "你是主智能体分配的子智能体，只负责一个赛题，不要切换到其他赛题。\n"
    "当前赛题: {title} (code={code})\n"
    "当前入口信息: {entrypoint}\n\n"
    "{previous_notes}\n\n"
    "关键: 每一步都要执行实际的 Bash 命令（curl/python3/nmap等），不要空想。"
)

CHILD_MISSION_FIRST_ROUND = (
    "你当前只处理赛题 {title} (code={code})。\n"
    "入口地址: {entrypoint}\n\n"
    "{context_from_notes}\n\n"
    "执行顺序:\n"
    "1. 启动实例\n"
    "2. 深度侦察（如已有预执行结果则直接分析）\n"
    "3. 分析技术栈和输入点\n"
    "4. 识别到具体产品时 search_poc_kb 搜索\n"
    "5. 按 OWASP Top 10 逐一检测漏洞\n"
    "6. 发现特定框架时使用对应利用脚本\n"
    "7. 获取 flag 并提交\n"
    "8. 停止实例\n"
    "9. 每个重要发现必须 save_challenge_note\n\n"
    "开始！"
)

RECON_ONLY_MISSION = (
    "你当前只处理赛题 {title} (code={code}) 的**侦察阶段**。\n"
    "入口地址: {entrypoint}\n\n"
    "{context_from_notes}\n\n"
    "★★★ 你的唯一目标是信息收集，严禁尝试任何漏洞利用或 flag 提交 ★★★\n\n"
    "执行顺序:\n"
    "1. 启动实例 (start_current_challenge)\n"
    "2. curl -sIL 获取响应头 → 识别技术栈\n"
    "3. curl -s 首页，分析HTML结构\n"
    "4. JS分析: curl -s TARGET/ | grep -oP 'src=\"[^\"]*\\.js\"' 提取JS后搜索API和密钥\n"
    "5. 手动测试: 对发现的输入点逐个测试常见漏洞\n"
    "6. 检查泄露路径: robots.txt / .git/config / .env / swagger / actuator\n"
    "7. ffuf 目录扫描\n"
    "8. 对发现的 API 端点 curl 测试未授权访问\n"
    "9. 识别到具体产品时 search_poc_kb 搜索\n"
    "10. 尝试默认凭据快速登录\n\n"
    "★★★ 侦察完成后必须 save_challenge_note 保存结构化报告 ★★★\n"
    "报告格式: [技术栈] [框架版本] [输入点] [疑似漏洞] [关键发现] [建议攻击方向]\n\n"
    "开始侦察！"
)

EXPLOIT_MISSION = (
    "你当前只处理赛题 {title} (code={code}) 的**漏洞利用阶段**。\n"
    "入口地址: {entrypoint}\n\n"
    "=== 侦察阶段的发现 ===\n{recon_findings}\n\n"
    "=== 策略指令（必须遵循） ===\n{attack_directions}\n\n"
    "★★★ 严格按照上述策略指令执行 ★★★\n\n"
    "执行步骤:\n"
    "1. 启动实例\n"
    "2. 按指定攻击方向依次尝试，优先使用对应 exploit 脚本\n"
    "3. 利用 search_vuln_kb / search_poc_kb 获取 payload\n"
    "4. 手动 curl 构造 payload 作为补充\n"
    "5. 发现 flag{{...}} 后立即 submit_current_flag\n"
    "6. 每个重要发现用 save_challenge_note 记录\n"
    "7. 一个方向 3 次无效就切换下一个\n"
    "8. 利用结束前执行通用 flag 提取\n"
    "9. 完成后停止实例\n\n"
    "开始利用！"
)

CHILD_MISSION_RETRY_ROUND = (
    "你当前只处理赛题 {title} (code={code})，这是第 {round_num} 轮续攻。\n"
    "入口地址: {entrypoint}\n\n"
    "★★★ 核心要求：基于之前发现探索新攻击面，严禁重复已尝试方法 ★★★\n\n"
    "=== 历史发现 ===\n{context_from_notes}\n\n"
    "=== 已失败方法 ===\n{failed_attempts}\n\n"
    "续攻策略:\n"
    "1. read_challenge_notes 回顾全部发现\n"
    "2. 分析哪些方向还没试过\n"
    "3. 用 curl/python3 手动做深度侦察\n"
    "4. 尝试全新的攻击方向\n"
    "5. 组合攻击：信息泄露获取的凭据 + 其他接口\n"
    "6. 如果16步以上仍无进展，用 search_poc_kb 检索更多漏洞\n"
    "7. 发现 flag{{...}} 后必须立即 submit_current_flag\n"
    "8. 完成后停止实例\n\n"
    "开始续攻！"
)
