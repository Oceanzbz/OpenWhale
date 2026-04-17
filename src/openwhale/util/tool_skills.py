"""Tool Skills — Agent 调用外部安全工具的技能接口。

提供给 Agent 的核心功能:
1. suggest_tools(scenario) — 根据场景推荐最合适的工具和命令
2. run_tool(tool_id, **params) — 执行工具并返回结果
3. get_tool_guide(tool_id) — 获取工具的完整使用指南
4. auto_install(tool_id) — 自动安装缺失的工具
5. get_skill_prompt() — 生成注入到Agent系统提示词中的工具技能清单
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from .tool_registry import TOOLS, ExternalTool, ToolRegistry, TOOLS_DIR

_registry = ToolRegistry()


def suggest_tools(scenario: str, target: str = "TARGET") -> str:
    """根据场景描述推荐最合适的工具和具体命令。"""
    matched = _registry.search(scenario, max_results=5)
    if not matched:
        return f"未找到匹配场景 '{scenario}' 的工具。可用工具:\n{_registry.list_all()}"

    lines = [f"=== 推荐工具 (场景: {scenario}) ===\n"]
    for tool in matched:
        installed = _registry.check_installed(tool.id)
        status = "✅已安装" if installed else "❌未安装"
        lines.append(f"★ {tool.name} [{status}]")
        lines.append(f"  {tool.description}")
        if tool.when_to_use:
            lines.append(f"  何时用: {tool.when_to_use}")

        for tpl in tool.usage_templates[:3]:
            cmd = tpl["cmd"].replace("{target}", target)
            lines.append(f"  → [{tpl['desc']}] {cmd}")

        if not installed and tool.install_cmd:
            lines.append(f"  安装: {tool.install_cmd}")
        if tool.notes:
            lines.append(f"  提示: {tool.notes}")
        lines.append("")

    return "\n".join(lines)


def run_tool(tool_id: str, timeout: int = 120, **params: str) -> str:
    """执行指定工具，返回stdout输出。"""
    tool = _registry.get_tool(tool_id)
    if not tool:
        return f"未知工具: {tool_id}。使用 suggest_tools() 搜索。"

    if not _registry.check_installed(tool_id):
        return (
            f"工具 {tool.name} 未安装。\n"
            f"安装命令: {tool.install_cmd}\n"
        )

    template_idx = int(params.pop("template", "0"))
    if template_idx >= len(tool.usage_templates):
        template_idx = 0

    cmd = tool.usage_templates[template_idx]["cmd"]
    for k, v in params.items():
        cmd = cmd.replace(f"{{{k}}}", v)

    unresolved = re.findall(r"\{(\w+)\}", cmd)
    if unresolved:
        return (
            f"命令中有未填充的参数: {unresolved}\n"
            f"完整模板: {cmd}\n"
            f"请提供这些参数。"
        )

    env = {
        **os.environ,
        "PATH": ":".join([
            os.environ.get("PATH", ""),
            os.path.expanduser("~/go/bin"),
            os.path.expanduser("~/.local/bin"),
            "/usr/local/go/bin",
        ]),
    }

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        output = result.stdout
        if result.stderr:
            output += "\n[stderr]\n" + result.stderr[-500:]
        if not output.strip():
            output = f"命令执行完成 (exit code: {result.returncode}), 无输出。"
        return output[:10000]
    except subprocess.TimeoutExpired:
        return f"命令超时 ({timeout}s): {cmd}"
    except Exception as exc:
        return f"执行失败: {exc}\n命令: {cmd}"


def auto_install(tool_id: str) -> str:
    """自动安装指定工具。"""
    tool = _registry.get_tool(tool_id)
    if not tool:
        return f"未知工具: {tool_id}"
    if _registry.check_installed(tool_id):
        return f"{tool.name} 已安装。"
    if not tool.install_cmd:
        return f"{tool.name} 需要手动安装(jar/binary)。"
    try:
        result = subprocess.run(
            tool.install_cmd, shell=True, capture_output=True, text=True,
            timeout=300,
            env={**os.environ, "PATH": os.environ.get("PATH", "") + ":" + os.path.expanduser("~/go/bin")},
        )
        if result.returncode == 0:
            return f"{tool.name} 安装成功。"
        return f"{tool.name} 安装失败:\n{result.stderr[-500:]}"
    except Exception as exc:
        return f"安装失败: {exc}"


def get_tool_guide(tool_id: str, target: str = "TARGET") -> str:
    """获取工具的完整使用指南。"""
    return _registry.format_usage(tool_id, target=target)


def get_status() -> str:
    """获取所有工具的安装状态。"""
    return _registry.get_status_report()


def get_skill_prompt() -> str:
    """生成注入到 Agent 系统提示词中的工具技能清单。

    让 Agent 知道有哪些外部工具可用、何时使用、如何使用。
    """
    lines = [
        "## 可用外部安全工具 (通过 shell 直接调用)",
        "",
        "以下工具已预装在远程服务器上。优先使用成熟工具而非手动构造 payload。",
        f"工具根目录: {TOOLS_DIR}",
        "",
    ]

    cat_names = {
        "scanner": "🔍 漏洞扫描",
        "recon": "📡 侦察/信息收集",
        "fuzzer": "💥 Fuzzing/目录发现",
        "exploit": "⚔️ Web漏洞利用",
        "java": "☕ Java漏洞利用",
        "intranet": "🏢 内网渗透",
        "tunnel": "🔗 隧道/代理/穿透",
        "privesc": "⬆️ 提权",
        "util": "🛠️ 辅助工具/字典",
    }

    categories: dict[str, list[ExternalTool]] = {}
    for t in TOOLS:
        categories.setdefault(t.category, []).append(t)

    for cat in ["scanner", "recon", "fuzzer", "exploit", "java", "intranet", "tunnel", "privesc", "util"]:
        tools = categories.get(cat, [])
        if not tools:
            continue
        tools.sort(key=lambda x: x.priority)
        lines.append(f"### {cat_names.get(cat, cat)}")
        for t in tools:
            top_cmd = t.usage_templates[0]["cmd"] if t.usage_templates else ""
            lines.append(f"- **{t.name}** (`{t.id}`): {t.description[:80]}")
            if t.when_to_use:
                lines.append(f"  何时用: {t.when_to_use}")
            if top_cmd:
                lines.append(f"  快速: `{top_cmd}`")
        lines.append("")

    lines.extend([
        "### 📋 使用决策树",
        "",
        "```",
        "目标 URL",
        "  ├─ 第一步: nuclei 全面扫描 / httpx 技术栈识别",
        "  ├─ SpringBoot → SBSCAN + dumpall + SpringBootExploit",
        "  ├─ Shiro → shiro_tool.jar (密钥爆破→CB链RCE)",
        "  ├─ Fastjson/Log4j → JNDIExploit.jar (JNDI注入)",
        "  ├─ ThinkPHP → ThinkPHP.jar (自动检测版本+RCE)",
        "  ├─ 通达OA → TongdaTools.jar",
        "  ├─ Flask SSTI → fenjing (自动WAF绕过)",
        "  ├─ 其他SSTI → SSTImap (多引擎)",
        "  ├─ Flask Session → flask-unsign (解码→爆破→伪造)",
        "  ├─ JWT → jwt_tool (alg:none→弱密钥→RS256混淆)",
        "  ├─ SQL注入 → sqlmap (自动化利用)",
        "  ├─ .git泄露 → git-dumper / GitHack",
        "  ├─ SSRF+Redis → Gopherus (生成gopher payload)",
        "  ├─ Redis未授权 → redis-rogue-server (RCE) / RedisWriteFile (写文件)",
        "  ├─ PHP反序列化 → phpggc (gadget链生成)",
        "  ├─ Java反序列化 → ysoserial / java-chains",
        "  ├─ 目录扫描 → ffuf (字典: ~/tools/SecLists/)",
        "  │",
        "  进入内网后:",
        "  ├─ 内网扫描 → fscan (一键扫描+暴破)",
        "  ├─ 域渗透 → impacket (PTH/DCSync) + kerbrute (枚举)",
        "  ├─ 域提权 → ZeroLogon / noPac",
        "  ├─ NTLM Relay → PetitPotam + ntlmrelayx",
        "  ├─ 隧道代理 → chisel / Stowaway / Neo-reGeorg",
        "  ├─ Linux提权 → linpeas (自动检测提权路径)",
        "  └─ 密码破解 → hashcat / john (字典: rockyou.txt)",
        "```",
        "",
        "### 备用exploit脚本 (scripts/exploits/) — 优先用curl/python3手动操作",
        "- `shiro_exploit.py` — Shiro密钥爆破+RCE",
        "- `fastjson_exploit.py` — Fastjson检测+利用",
        "- `log4j_scan.py` — Log4j全Header检测",
        "- `struts2_scan.py` — Struts2全版本扫描+RCE",
        "- `thinkphp_exploit.py` — ThinkPHP全版本利用",
        "- `nacos_exploit.py` — Nacos利用+配置导出",
        "- `ssrf_exploit.py` — SSRF利用(Gopher打Redis/MySQL)",
        "- `oa_exploit.py` — 国内OA综合利用",
        "",
        "### 使用原则",
        "1. 侦察阶段: nuclei/httpx 批量扫描 → fscan 内网扫描",
        "2. 识别技术栈: 选择对应的专用利用工具",
        "3. 优先用成熟工具而非手动构造 payload",
        f"4. 字典路径: {TOOLS_DIR}/SecLists/ | {TOOLS_DIR}/PayloadsAllTheThings/",
        f"5. 密码字典: {TOOLS_DIR}/intranet/rockyou.txt",
    ])

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# 场景快捷方法 — Agent 可直接调用
# ═══════════════════════════════════════════════════════════════

def quick_nuclei_scan(target: str, tags: str = "") -> str:
    """快速 Nuclei 漏洞扫描。"""
    if tags:
        return run_tool("nuclei", target=target, tag=tags, template="5")
    return run_tool("nuclei", target=target, template="0")


def quick_dir_scan(target: str) -> str:
    """快速目录扫描。"""
    if _registry.check_installed("ffuf"):
        return run_tool("ffuf", target=target, template="0")
    if _registry.check_installed("dirsearch"):
        return run_tool("dirsearch", target=target, template="0")
    return "ffuf 和 dirsearch 均未安装"


def quick_sqli_test(target_url: str) -> str:
    """快速SQL注入检测。"""
    return run_tool("sqlmap", target=target_url, template="0")


def quick_ssti_test(target_url: str) -> str:
    """快速SSTI检测(优先fenjing,备选SSTImap)。"""
    if _registry.check_installed("fenjing"):
        return run_tool("fenjing", target=target_url, template="0")
    if _registry.check_installed("sstimap"):
        return run_tool("sstimap", target=target_url, template="0")
    return "fenjing 和 SSTImap 均未安装"


def quick_flask_crack(cookie: str) -> str:
    """快速Flask Session爆破。"""
    return run_tool("flask_unsign", cookie=cookie, template="1")


def quick_springboot_scan(target: str) -> str:
    """SpringBoot漏洞扫描: SBSCAN + dumpall。"""
    results = []
    if _registry.check_installed("sbscan"):
        results.append("=== SBSCAN ===")
        results.append(run_tool("sbscan", target=target))
    if _registry.check_installed("springboot_scan"):
        results.append("=== SpringBoot-Scan ===")
        results.append(run_tool("springboot_scan", target=target))
    return "\n".join(results) if results else "SBSCAN 和 SpringBoot-Scan 均未安装"


def quick_java_deser(chain: str, command: str) -> str:
    """快速生成Java反序列化payload(base64)。"""
    return run_tool("ysoserial", command=command, template="1" if chain.startswith("CC") else "2")


def quick_fscan(target_cidr: str) -> str:
    """快速内网扫描。"""
    return run_tool("fscan", target=target_cidr, template="0")


def quick_redis_exploit(target: str, attacker_ip: str) -> str:
    """快速Redis RCE(主从复制)。"""
    return run_tool("redis_rogue", target=target, attacker_ip=attacker_ip)
