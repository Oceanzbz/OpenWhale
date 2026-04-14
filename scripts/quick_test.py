#!/usr/bin/env python3
"""快速连通性测试 - 无需安装任何依赖，用原生 Python 验证平台和模型连通性。"""

import json
import os
import sys
import urllib.request
import urllib.error

# ─── 从 .env 加载配置 ────────────────────────────────────────
def load_env(path=".env"):
    if not os.path.exists(path):
        print(f"[!] 未找到 {path}，尝试从环境变量读取")
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

load_env()

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
SERVER_HOST = os.environ.get("SERVER_HOST", "")
MODEL_BASE_URL = os.environ.get("MODEL_BASE_URL", "")
MODEL_ID = os.environ.get("MODEL_ID", "ep-jsc7o0kw")
TOKENHUB_API_KEY = os.environ.get("TOKENHUB_API_KEY", "")

print("=" * 60)
print("  OpenWhale 连通性快速测试")
print("=" * 60)
print(f"  Server Host:   {SERVER_HOST}")
print(f"  Model Base:    {MODEL_BASE_URL}")
print(f"  Model ID:      {MODEL_ID}")
print(f"  Token:         {AGENT_TOKEN[:16]}..." if AGENT_TOKEN else "  Token: (未配置)")
print()

errors = 0

# ─── 测试 1: API 接口 ────────────────────────────────────────
print("[1/3] 测试赛题 API 接口...")
try:
    req = urllib.request.Request(
        f"http://{SERVER_HOST}/api/challenges",
        headers={"Agent-Token": AGENT_TOKEN},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        if data.get("code") == 0:
            d = data["data"]
            print(f"  ✓ 连接成功！关卡 {d['current_level']} | 赛题 {d['total_challenges']} 道 | 已完成 {d['solved_challenges']} 道")
            for ch in d.get("challenges", []):
                flag = "✓" if ch["flag_got_count"] >= ch["flag_count"] else "○"
                status = ch.get("instance_status", "?")
                print(f"    {flag} [{ch['difficulty']:6s}] {ch['title']:30s} code={ch['code']}  [{status}]  {ch['total_got_score']}/{ch['total_score']}分")
        else:
            print(f"  ✗ API 返回错误: {data.get('message', data)}")
            errors += 1
except urllib.error.HTTPError as e:
    print(f"  ✗ HTTP 错误 {e.code}: {e.reason}")
    errors += 1
except Exception as e:
    print(f"  ✗ 连接失败: {e}")
    print(f"    (调试模式下 CVM 无法连接靶机平台，这是正常的)")
    errors += 1

# ─── 测试 2: MCP 接口 ────────────────────────────────────────
print()
print("[2/3] 测试 MCP 服务器...")
try:
    mcp_payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "quick_test", "version": "0.1"},
        },
        "id": 1,
    }).encode()
    req = urllib.request.Request(
        f"http://{SERVER_HOST}/mcp",
        data=mcp_payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AGENT_TOKEN}",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        mcp_data = json.loads(resp.read().decode())
        if "result" in mcp_data:
            server_info = mcp_data["result"].get("serverInfo", {})
            print(f"  ✓ MCP 连接成功！服务器: {server_info.get('name', '?')} v{server_info.get('version', '?')}")
        elif "error" in mcp_data:
            print(f"  ✗ MCP 错误: {mcp_data['error']}")
            errors += 1
        else:
            print(f"  ~ MCP 响应: {str(mcp_data)[:200]}")
except Exception as e:
    print(f"  ✗ MCP 连接失败: {e}")
    errors += 1

# ─── 测试 3: 模型网关 ────────────────────────────────────────
print()
print("[3/3] 测试模型网关...")
try:
    model_payload = json.dumps({
        "model": MODEL_ID,
        "messages": [{"role": "user", "content": "Say OK"}],
        "max_tokens": 10,
    }).encode()
    req = urllib.request.Request(
        f"{MODEL_BASE_URL}/chat/completions",
        data=model_payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKENHUB_API_KEY}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        model_data = json.loads(resp.read().decode())
        choices = model_data.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content", "(空)")
            model_name = model_data.get("model", MODEL_ID)
            print(f"  ✓ 模型响应成功！模型: {model_name}")
            print(f"    模型回复: {content[:100]}")
        else:
            print(f"  ✗ 模型无有效回复: {str(model_data)[:200]}")
            errors += 1
except urllib.error.HTTPError as e:
    body = e.read().decode() if hasattr(e, "read") else ""
    print(f"  ✗ 模型网关 HTTP {e.code}: {e.reason}")
    if body:
        print(f"    响应: {body[:200]}")
    errors += 1
except Exception as e:
    print(f"  ✗ 模型网关连接失败: {e}")
    errors += 1

# ─── 总结 ────────────────────────────────────────────────────
print()
print("=" * 60)
if errors == 0:
    print("  ✅ 所有测试通过！可以运行: ./start.sh")
else:
    print(f"  ⚠️  {errors} 项测试未通过")
    print("  调试模式下靶机平台不通是正常的，但模型网关必须能通")
print("=" * 60)

sys.exit(errors)
