# OpenWhale

> **LLM 驱动的自动化 CTF/Web 渗透测试智能体**  
> 基于 DeepAgents + MCP 协议，具备并发攻击、持久化记忆、启发式方向推导能力。

---

## 设计思想

OpenWhale 将渗透测试的专家经验系统化，以 LLM 为决策核心，工具链为执行手段，实现对 Web 漏洞的自主发现与利用。

**三大原则：**

- **启发式驱动**：侦察发现自动映射攻击方向，而非硬编码规则
- **上下文管理优先**：Python 脚本精确提取关键字段，笔记系统跨运行复用，拒绝上下文污染
- **并发隔离**：最多同时攻击 3 道题，每道题子 Agent 完全隔离，互不干扰

---

## 核心能力

| 模块 | 功能 |
|------|------|
| **三阶段流水线** | 侦察 → 利用 → 深挖（hard 题），每阶段独立子 Agent |
| **攻击启发式** | 40+ 关键词规则，从侦察文本自动推导攻击方向（SSRF/SQLi/原型链/供应链等） |
| **Skills 技能库** | Markdown 驱动的模块化知识库，按难度动态加载 payload 模板 |
| **续攻学习** | 失败方向自动分类，续攻轮强制选择新方向，避免重复劳动 |
| **三重 Flag 兜底** | auto-flag + API 探测脚本 + 静态路径批量探测 |
| **持久化记忆** | 笔记/缓存/情报跨运行保留，重启后自动恢复上下文 |
| **持续运行** | 完成所有题目前自动循环，支持后台 `nohup`/`screen` 运行 |

---

## 快速开始

### 1. 环境要求

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)（包管理）

### 2. 安装

```bash
git clone <repo_url> && cd OpenWhale-main-v2
pip install uv
uv sync
```

### 3. 配置

```bash
cp .env.example .env
```

编辑 `.env`，填写必填项：

```env
# ── 必填 ─────────────────────────────────────────
AGENT_TOKEN=<比赛平台 Agent Token>
SERVER_HOST=<比赛平台 Server Host（自动拼接 /mcp）>
TOKENHUB_API_KEY=<OpenAI 兼容 API Key>

# ── 模型配置 ──────────────────────────────────────
MODEL_BASE_URL=https://tokenhub.tencentmaas.com/v1
MODEL_NAME=MiniMax-M2.7
MODEL_ID=ep-jsc7o0kw

# ── 运行后端（推荐 deepagents）─────────────────────
AGENT_BACKEND=deepagents

# ── 回连 IP（Blind XSS / XXE OOB 等需要外带数据时使用）──
CALLBACK_IP=<你的公网 IP>

# ── 持续运行配置 ──────────────────────────────────
AUTOPILOT_AGENT_COMMAND=".venv/bin/openwhale"
AUTOPILOT_START_DELAY_SECONDS=10
AUTOPILOT_CYCLE_INTERVAL_SECONDS=5
AUTOPILOT_MAX_CYCLES=0
```

### 4. 运行

```bash
# 前台运行（开发调试）
uv run openwhale

# 后台持续运行（推荐比赛时使用）
nohup bash -c "set -a; source .env; set +a; .venv/bin/python scripts/delayed_autopilot.py" \
  >> logs/autopilot.log 2>&1 &

# 或使用 screen
screen -dmS openwhale bash -c "set -a; source .env; set +a; \
  .venv/bin/python scripts/delayed_autopilot.py >> logs/autopilot.log 2>&1"

# 仅启动 Web 监控界面
uv run openwhale-web
```

运行后访问 `http://localhost:8080` 实时监控进度。

---

## 项目结构

```
OpenWhale-main-v2/
├── src/openwhale/
│   ├── main.py                     # 主入口
│   ├── agents/
│   │   ├── deepagents_agent.py     # 核心：并发主从架构（v10b）
│   │   ├── attack_heuristics.py    # 启发式攻击方向推导引擎
│   │   ├── bash_executor.py        # 异步 Bash 执行器
│   │   ├── base.py                 # 智能体基类
│   │   ├── factory.py              # 智能体工厂
│   │   ├── openai_agent.py         # OpenAI 兼容实现
│   │   └── claude_code_agent.py    # Claude Code SDK 实现
│   ├── prompts/
│   │   └── builder.py              # 分层 Prompt 构建器（难度感知）
│   ├── skills/                     # Markdown 技能知识库
│   │   ├── core/
│   │   │   ├── identity.md         # 角色定义
│   │   │   ├── rules.md            # 15 条行为约束
│   │   │   └── available_tools.md  # 工具清单（含 CVM 渗透工具）
│   │   ├── methodology/
│   │   │   ├── recon.md            # 侦察方法论
│   │   │   ├── exploit.md          # 漏洞利用方法论
│   │   │   └── ctf_bypass.md       # CTF 实战绕过技巧
│   │   └── vulnerabilities/
│   │       ├── owasp_top10.md      # OWASP Top 10 检查清单
│   │       ├── cve_patterns.md     # CVE 利用模式
│   │       └── advanced_exploit.md # 高级利用手册（SSRF/原型链/XXE OOB 等）
│   ├── web/
│   │   └── app.py                  # FastAPI + SSE 实时监控
│   └── util/
│       ├── mcp_client.py           # MCP 协议客户端
│       ├── notes.py                # 持久化笔记系统
│       ├── cache.py                # 侦察结果缓存
│       └── vuln_kb.py              # 漏洞知识库 + POC
├── scripts/
│   └── delayed_autopilot.py        # 持续运行控制脚本
├── data/                           # 运行时持久化数据（笔记/缓存）
├── logs/                           # 运行日志
├── .env.example                    # 环境变量模板
├── ARCHITECTURE.md                 # 架构与演进详细报告
└── pyproject.toml
```

---

## 攻击能力覆盖

**自动识别并利用的漏洞类型：**

| 类别 | 具体漏洞 |
|------|---------|
| 注入类 | SQL 注入（含 WAF 绕过）、命令注入、SSTI（Jinja2 深度利用）、NoSQL 注入、LDAP 注入 |
| SSRF | 基础 SSRF、协议利用（file/gopher/dict）、IP 变体绕过、内网服务探测与利用 |
| 反序列化 | Python Pickle RCE、YAML 反序列化、Java 反序列化（impacket）|
| 原型链污染 | Node.js `__proto__`、PyDash `set_`/`merge` 路径 |
| XXE | 基础实体读文件、参数实体 OOB 外带、OOXML（docx/xlsx）XXE |
| XSS | 反射/存储 XSS、Blind XSS（支持回连收 Cookie）|
| 身份认证 | 默认凭据、SQL 注入绕过、JWT 伪造（alg:none/弱密钥）、Magic Hash、Session 篡改 |
| 访问控制 | IDOR、强制浏览、API 未授权访问、HTTP 方法/路径变体绕过 |
| 文件操作 | LFI/路径穿越、文件上传绕过（MIME/扩展名/Magic Bytes）|
| 供应链 | 依赖混淆、构建流水线注入、镜像替换 |
| 内网渗透 | IP 段批量扫描、Redis/MySQL 未授权、内部 API 枚举 |
| CVE 利用 | Log4Shell、Spring4Shell、Shiro 反序列化、WebLogic、ThinkPHP、Nacos 等 |

---

## CVM 渗透工具链

在 CVM（`ubuntu@101.35.19.108`）上已预装：

```
隧道代理:  chisel  frpc/frps  proxychains4  socat
端口扫描:  nmap  masscan
目录枚举:  ffuf  gobuster  nikto
漏洞利用:  sqlmap  hydra
数据库:    redis-cli  mysql
网络:      curl  nc/netcat  sshpass  dig  whois
Python:    requests  paramiko  lxml  impacket  pyyaml
```

---

## 环境变量完整说明

| 变量名 | 必填 | 默认值 | 说明 |
|--------|:----:|--------|------|
| `AGENT_TOKEN` | ✅ | — | 竞赛平台 Agent Token（MCP 鉴权）|
| `SERVER_HOST` | ✅ | — | 竞赛平台 Server Host |
| `TOKENHUB_API_KEY` | ✅ | — | OpenAI 兼容 API Key |
| `AGENT_BACKEND` | ❌ | `deepagents` | 智能体基座（`deepagents` / `openai_compat` / `claude_code`）|
| `MODEL_BASE_URL` | ❌ | `https://tokenhub.tencentmaas.com/v1` | 模型网关地址 |
| `MODEL_NAME` | ❌ | `MiniMax-M2.7` | 模型显示名称 |
| `MODEL_ID` | ❌ | `ep-jsc7o0kw` | 实际调用模型 ID |
| `CALLBACK_IP` | ❌ | `YOUR_PUBLIC_IP` | 公网回连 IP（Blind XSS/XXE OOB）|
| `DEEPAGENTS_RECURSION_LIMIT` | ❌ | `400` | DeepAgents 图递归上限 |
| `DEEPAGENTS_TIMEOUT_SECONDS` | ❌ | `1800` | 单次运行超时（秒）|
| `DEEPAGENTS_BASH_TIMEOUT_SECONDS` | ❌ | `120` | Bash 命令超时（秒）|
| `DEEPAGENTS_BASH_MAX_OUTPUT_CHARS` | ❌ | `8000` | Bash 输出截断长度 |
| `AUTOPILOT_AGENT_COMMAND` | ❌ | `.venv/bin/openwhale` | 每轮实际执行命令 |
| `AUTOPILOT_START_DELAY_SECONDS` | ❌ | `10` | 首轮启动前延时（秒）|
| `AUTOPILOT_CYCLE_INTERVAL_SECONDS` | ❌ | `5` | 轮次间隔（秒）|
| `AUTOPILOT_MAX_CYCLES` | ❌ | `0` | 最大轮次（0 = 不限）|
| `LOG_LEVEL` | ❌ | `INFO` | 日志级别 |
| `WEB_ENABLED` | ❌ | `true` | 是否启动 Web 界面 |
| `WEB_PORT` | ❌ | `8080` | Web 监控端口 |

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言/运行时 | Python 3.12+ / [uv](https://github.com/astral-sh/uv) |
| LLM 接入 | OpenAI Python SDK（兼容 MiniMax/其他 OpenAI 兼容接口）|
| Agent 编排 | [deepagents](https://github.com/langchain-ai/deepagents) + LangGraph |
| 平台接入 | [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/python-sdk) |
| Web 监控 | FastAPI + Server-Sent Events |
| 日志 | loguru + rich |

---

## 深入了解

完整的架构设计、版本演进过程和未来改进计划，请阅读：

📄 **[ARCHITECTURE.md](./ARCHITECTURE.md)**

---

## 许可

本项目为竞赛用途开发，仅限授权环境内使用。请勿用于未授权的渗透测试。
