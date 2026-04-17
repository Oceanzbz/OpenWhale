# OpenWhale 系统架构与演进报告

> 本报告记录 OpenWhale 智能渗透测试系统从 v5 到 v10b 的完整设计思想、架构演进和未来改进方向。

---

## 一、核心设计思想

### 1.1 基本理念：LLM + 工具链驱动的自动化渗透

OpenWhale 的核心理念是将 CTF/渗透测试的专家经验系统化，通过 LLM（大语言模型）作为"大脑"，工具链作为"手臂"，实现对 Web 漏洞的自主发现和利用。

```
赛题平台 (MCP)
      │
      ▼
 PromptBuilder ──── Skills 技能库
      │               (Markdown 文档)
      ▼
 DeepAgents 调度器
      │
      ├──▶ 侦察 SubAgent ──▶ Bash(curl/nmap/ffuf)
      ├──▶ 利用 SubAgent ──▶ Python3/SQLMap/自定义脚本
      └──▶ 深挖 SubAgent ──▶ 续攻/组合漏洞链
                │
                ▼
           MCP submit_flag
```

### 1.2 三大设计原则

**① 启发式驱动，而非规则驱动**  
不硬编码"遇到登录页就试 SQL 注入"的规则，而是通过 `attack_heuristics.py` 将侦察发现（响应头、框架特征、功能关键词）映射为优先攻击方向，由 LLM 自主判断执行顺序。

**② 上下文管理优先**  
LLM 的 context window 是稀缺资源。系统全程：
- 用 Python 脚本精确提取关键字段，禁止将完整 HTML/JSON 喂给模型
- 笔记系统（`PentestNotes`）持久化关键发现，跨运行复用
- 侦察缓存（`ResultCache`）避免重复侦察

**③ 并发隔离 + 顺序控制**  
- 最大并发 3 道题同时攻击（`asyncio.Semaphore(3)`）
- `start_challenge` 顺序串行执行（`asyncio.Lock`），防止平台接口过载
- 每道题的子 Agent 完全隔离，各自维护独立的工具集和上下文

---

## 二、核心架构模块

### 2.1 调度层（`run_competition`）

大循环：每 30 秒 `list_challenges` 刷新题目列表，检测未解赛题，分批并发启动子 Agent。每道题经历最多 5 个内轮（1侦察 + 4续攻），充分挖掘后才放弃。

```python
# 伪代码
while True:
    challenges = list_challenges()
    unsolved = [c for c in challenges if not solved(c)]
    if not unsolved: wait(30); continue
    
    async with Semaphore(3):
        for challenge in unsolved:
            await run_single_challenge(challenge, round=current_round)
```

### 2.2 三阶段攻击流水线（`_run_single_challenge_agent`）

```
Phase 1: Recon（侦察）
  ↓ 发现技术栈/输入点/功能结构
  ↓ save_challenge_note 持久化

Phase 2: Exploit（利用）
  ↓ attack_heuristics 推导攻击方向
  ↓ LLM 按优先级依次尝试

Phase 3: Deep Dive（深挖，medium/hard题）
  ↓ 加载已失败方向分类
  ↓ 强制选择全新未尝试方向

→ auto-flag 机制兜底
→ API 探测脚本兜底
```

### 2.3 技能系统（Skills + PromptBuilder）

技能系统借鉴 Claude Code 的 `buildEffectiveSystemPrompt` 分层设计：

| 层级 | 内容 | 文件 |
|------|------|------|
| 身份层 | 角色定义、环境区分 | `skills/core/identity.md` |
| 规则层 | 15 条行为约束 | `skills/core/rules.md` |
| 工具层 | 完整工具清单+用法 | `skills/core/available_tools.md` |
| 技能层 | 方法论+漏洞知识 | `skills/methodology/` + `skills/vulnerabilities/` |
| 上下文层 | 历史笔记+侦察缓存 | 运行时动态注入 |
| 任务层 | 具体 mission 指令 | `PromptBuilder.build_*_mission()` |

**难度感知**：easy 题只加载精简技能集，medium/hard 加载完整技能（含高级利用手册）。

### 2.4 攻击启发式（`attack_heuristics.py`）

三类规则引擎，从侦察文本中提取关键词自动推导攻击方向：

- `_FRAMEWORK_RULES`：框架指纹 → 框架特有漏洞（FastAPI/Flask/PyDash/Shiro/Spring 等 12 条）
- `_FUNCTIONALITY_RULES`：功能关键词 → 功能漏洞（文件上传/SSO/竞态/供应链/Blind XSS 等 11 条）
- `_VULN_CLASS_RULES`：漏洞模式 → 利用指导（SSRF/XXE/内网/GraphQL/Redis 等 16 条）

### 2.5 自动Flag提取机制

三重兜底，防止 LLM 主观遗漏 flag：

1. **auto-flag**：监听所有 tool_end 事件，正则扫描工具输出，自动提交
2. **API 探测脚本**（`_API_PROBE_TEMPLATE`）：每道题结束前自动生成 Python 脚本，遍历所有 API 端点，反向用字段名探测参数
3. **静态路径探测**：批量 curl `/flag`、`/flag.txt`、`/api/flag`、`/.env`、`/debug` 等常见路径

### 2.6 持久化系统

```
data/
├── notes/          # PentestNotes - 每道题的发现记录（JSON）
│   ├── {code}.json   # 按题目 code 存储
│   └── global.json   # 全局情报（跨题线索）
├── cache/          # ResultCache - 侦察结果缓存
└── vuln_kb/        # VulnKnowledgeBase - 漏洞知识库 + POC
```

---

## 三、迭代演进过程

### v5 → v6（基础能力建设）
- 初始版本：单 Agent 串行攻击，无并发
- 问题：上下文爆炸（大 HTML 未处理），无笔记复用，每轮从零开始

### v7（并发重构 + 关键修复）

**核心变化：**
- 引入 `asyncio.Semaphore(3)` 并发 3 题
- `start_challenge` 改为串行锁，防止容器平台过载
- `BashExecutor` flag 自动保留（防超时丢失）
- `_try_extract_flags` 通用化（首次引入 API 探测脚本）
- 侦察笔记持久化，续攻轮注入历史发现
- 增加英文关键词支持（`_start_challenge_sequential`）

**解决：** 管理混乱、并发未实现、脚本工具冗余（删除 `js_analyzer.py`/`vuln_scanner.py`）

---

### v8（策略优化 + Bug 修复）

**核心变化：**
- 假 flag 过滤（`_is_fake_flag`），防止 `flag{test_flag}` 重复提交 5 次的问题
- `KeyError: 'content'` 修复（`notes.py` 改用 `.get('content', str(n))`）
- 删除全局策略 LLM（形同虚设，17 题只决策 3 题），改为启发式分配
- Bash 默认超时从 120s 降至 60s
- 内轮数从 3 轮增至 5 轮

**解决：** 假 flag 污染、KeyError 崩溃、策略 LLM 浪费 token

---

### v9（学习能力 + 竞态修复）

**核心变化：**
- **续攻学习**：引入 `_classify_failed_directions()`，将历史失败命令归类（SQL注入/SSRF/文件上传等），注入续攻 prompt，强制选择新方向
- **探测脚本竞态修复**：`/tmp/_owprobe.py` → `/tmp/_owprobe_{challenge_code}.py`，3并发不再互相覆盖
- **submit 节流**：`_throttled_submit()`，最小间隔 1.5s，防止速率限制
- **预算恢复**：v8 过度压缩导致 Agent 刚起步就超时，v9 恢复合理预算
- **平台降级保护**：`_last_good_challenges` 缓存，防止 API 返回空列表时清空任务队列
- **自启动修复**：`delayed_autopilot.py` 修复早退逻辑和命令路径

**解决：** 重复失败（同一攻击方向死磕）、并发竞态、超时过快

---

### v10（知识注入 + 工具链扩展）

**核心变化：**
- **新增 `advanced_exploit.md`**：SSRF 链式/协议利用、PyDash 原型链、Pickle 反序列化、供应链投毒、Blind XSS + 回连、XXE OOB、SSTI 深度利用 — 全部带 payload 模板
- **`attack_heuristics.py` 大扩展**：新增内网渗透/GraphQL/货运追踪/供应链/Blind XSS/业务逻辑/诊断面板共 12 条规则；题目关键词映射增至 27 个
- **CALLBACK_IP 动态注入**：环境变量 `CALLBACK_IP=101.35.19.108`，Blind XSS/XXE OOB payload 自动替换为真实公网 IP
- **命令超时强制**：prompt 中写入所有 `curl` 加 `-m 10`，`requests.get` 加 `timeout=10`
- **内网渗透策略**：Python3 批量扫描模板注入 prompt
- **CVM 工具链**：安装 chisel/frp/proxychains4/socat/hydra/gobuster/masscan/redis-cli/mysql/nikto + Python 库 paramiko/lxml/impacket

**解决：** 内网探测无工具/无知识、SSRF 不知如何深度利用、Blind XSS 无回连、超时命令频繁卡死

---

### v10b（关键 Bug 修复）

**核心变化（来自日志分析）：**

| 问题 | 数据 | 修复方案 |
|------|------|---------|
| Bash 拦截误杀 LFI 攻击 | 70次误拦 | 拦截规则改为只拦截本地 agent 日志，不拦截含 `curl/http://` 的请求 |
| auto-flag 误提交代码片段 | 296次误提交 | 正则改为 `flag\{[^}\s]{6,80}\}`，`_is_fake_flag` 新增代码指标检测 |
| 816次"实例未运行"噪音 | 816次 | 主因为 auto-flag 误触发（已通过上条修复大幅减少） |

---

## 四、未来改进方向

### 4.1 🔴 高优先级（核心能力缺口）

**① 真正的 Blind XSS 闭环**
目前 Blind XSS 只注入 payload，无法等待管理员触发后接收 Cookie 并利用。
- 需要：后台常驻 HTTP 监听服务（已安装 python3，可用 `nohup` 启动）
- 建议：在 `_run_single_challenge_agent` 开始前自动启动监听，结束时扫描收到的数据

**② SSRF → 内网服务利用的完整闭环**
发现 SSRF 后能枚举内网 IP，但对发现的内网服务（Redis/MySQL/内部 API）缺乏自动化深度利用。
- 需要：SSRF payload 库（gopher 打 Redis 的完整 URL 生成器）
- 建议：在 `_try_extract_flags` 中增加 SSRF 探测 → 内网服务 → flag 提取的完整链路

**③ 学习记忆跨周期保留**
目前 `_classify_failed_directions` 只在同一周期内有效，重启 agent 后失去所有失败记录。
- 需要：将失败方向写入 `notes` 持久化，跨运行恢复
- 建议：在 `_record_challenge_failure` 中追加失败类别到笔记文件

### 4.2 🟡 中优先级（效率提升）

**④ 动态步数预算**
目前所有 easy/medium/hard 题使用统一步数预算。应根据每道题的发现质量动态调整：
- 侦察发现大量可利用点 → 增加 exploit 步数
- 前几轮均为 500 错误 → 缩短超时，快速跳过

**⑤ 跨题情报共享**
发现内网 IP `10.0.169.17` 上运行的服务，可能对其他题目也有用。
- 建议：`GlobalIntel` 类增加"已发现内网主机/端口"列表，所有题目的子 Agent 启动时注入

**⑥ Flag 格式动态适配**
部分赛题 flag 不是标准 `flag{...}` 格式（可能是 UUID、纯哈希值等）。
- 建议：在侦察阶段尝试 `view_hint` 推断 flag 格式，动态更新正则

**⑦ 命令超时自适应**
`curl -m 10` 对某些内网扫描太短，对简单 API 又太长。
- 建议：根据目标类型动态设置超时（公网 API 10s，内网扫描 2s/host，nmap 30s）

### 4.3 🟢 低优先级（工程质量）

**⑧ 并发数动态调节**
当前固定并发 3，比赛平台最大容量可能不同。
- 建议：从 `list_challenges` 响应头或配置文件读取最大并发数

**⑨ 提示词版本管理**
每次优化都在代码里直接改字符串，没有版本历史。
- 建议：将各 `build_*_mission` 的关键模板提取到 `skills/prompts/` 目录，用 Markdown 管理

**⑩ 结构化比赛报告**
比赛结束后生成 HTML 报告（每道题的技术栈/漏洞类型/利用路径/是否解出）。
- 建议：在 `run_competition` 结束时从 `notes` 读取所有记录，生成 JSON + HTML 摘要

**⑪ 安全审计**
- `bash_tool` 的拦截规则需要更完善（白名单机制替代黑名单）
- `_is_fake_flag` 的字符集过滤（`[a-zA-Z0-9_\-+=...]`）可能误杀包含特殊字符的真实 flag
- 建议：对 `_is_fake_flag` 中字符集过滤设置开关，或改为宽松模式+人工二次确认

---

## 五、关键数据汇总

| 版本 | 主要成就 | 遗留问题 |
|------|---------|---------|
| v7 | 实现真正并发 3 题、删除冗余工具 | 假 flag 污染、KeyError 崩溃 |
| v8 | 假 flag 过滤、5 轮续攻 | 预算压缩过度、重复失败 |
| v9 | 续攻学习、竞态修复、节流 | 知识库不足（SSRF/原型链/供应链） |
| v10 | 高级漏洞知识注入、工具链扩展 | 拦截规则误杀、auto-flag 乱提交 |
| v10b | 拦截修复、auto-flag 精确过滤 | Blind XSS 无闭环、内网链路不完整 |

---

*报告生成时间：2026-04-17*
