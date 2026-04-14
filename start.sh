#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# OpenWhale 一键启动脚本
# 用法:
#   ./start.sh          — 单次运行（调试模式推荐）
#   ./start.sh auto     — 自动循环模式（答题模式推荐）
#   ./start.sh test     — 仅测试连通性
#   ./start.sh install  — 仅安装依赖
# ═══════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║   🐋 OpenWhale 渗透测试智能体 v0.1   ║"
    echo "  ║   腾讯云黑客松·智能渗透挑战赛         ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${CYAN}[→]${NC} $1"; }

# ─── 检查并加载 .env ─────────────────────────────────────────
check_env() {
    if [ ! -f .env ]; then
        log_error ".env 文件不存在！请先配置: cp .env.example .env && vim .env"
        exit 1
    fi

    # 加载环境变量（逐行解析，跳过注释和空行，正确处理带空格的值）
    while IFS='=' read -r key value; do
        # 跳过注释和空行
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # 去除 key 两端空格
        key=$(echo "$key" | xargs)
        # 去除 value 两端空格和引号
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^["'\'']\(.*\)["'\'']$/\1/')
        # 导出
        export "$key=$value" 2>/dev/null || true
    done < .env

    # 检查必填项
    local missing=0
    if [ -z "$AGENT_TOKEN" ] || [ "$AGENT_TOKEN" = "your-agent-token-here" ]; then
        log_error "AGENT_TOKEN 未配置"
        missing=1
    fi
    if [ -z "$SERVER_HOST" ] || [ "$SERVER_HOST" = "your-server-host" ]; then
        log_error "SERVER_HOST 未配置"
        missing=1
    fi
    if [ -z "$TOKENHUB_API_KEY" ] || [ "$TOKENHUB_API_KEY" = "your-tokenhub-api-key-here" ]; then
        log_error "TOKENHUB_API_KEY 未配置"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        log_error "请编辑 .env 文件填写必要的配置项"
        exit 1
    fi

    log_info "配置加载完成"
    echo "       Agent Token: ${AGENT_TOKEN:0:16}..."
    echo "       Server Host: $SERVER_HOST"
    echo "       Model Base:  $MODEL_BASE_URL"
    echo "       Backend:     $AGENT_BACKEND"
}

# ─── 安装依赖 ────────────────────────────────────────────────
install_deps() {
    log_step "检查 Python 环境..."

    if ! command -v python3 &>/dev/null; then
        log_error "未找到 python3，请先安装 Python 3.12+"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log_info "Python 版本: $PYTHON_VERSION"

    # 安装 uv
    if ! command -v uv &>/dev/null; then
        log_step "安装 uv 包管理器..."
        pip install uv 2>/dev/null || pip3 install uv 2>/dev/null
    fi
    log_info "uv 已就绪: $(uv --version 2>/dev/null || echo 'installed')"

    # 使用清华 PyPI 镜像加速（CVM 内网到官方 PyPI 可能很慢）
    export UV_INDEX_URL="${UV_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
    log_info "PyPI 镜像: $UV_INDEX_URL"

    # 去掉不必要的重型依赖（claude-agent-sdk ~70MB，仅 claude_code 后端使用）
    if [ "$AGENT_BACKEND" != "claude_code" ]; then
        sed -i '/"claude-agent-sdk/d' pyproject.toml 2>/dev/null || true
        sed -i '/"anthropic/d' pyproject.toml 2>/dev/null || true
    fi

    # 安装项目依赖
    log_step "安装项目依赖（uv sync）..."
    uv sync
    log_info "项目依赖安装完成"

    # 创建数据目录
    mkdir -p data logs
    log_info "数据目录已就绪: data/ logs/"

    # 检查渗透工具
    log_step "检查渗透工具..."
    local tools=("curl" "nmap" "python3" "jq")
    local optional_tools=("sqlmap" "ffuf" "dirsearch" "nuclei")

    for t in "${tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            log_info "$t ✓"
        else
            log_warn "$t 未安装（基础工具，建议安装: sudo apt install $t）"
        fi
    done

    for t in "${optional_tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            log_info "$t ✓"
        else
            log_warn "$t 未安装（可选，智能体会用 curl+python3 替代）"
        fi
    done
}

# ─── 连通性测试 ──────────────────────────────────────────────
test_connectivity() {
    log_step "测试平台连通性..."

    # 测试 MCP Server
    local MCP_URL="http://${SERVER_HOST}/mcp"
    log_step "测试 MCP 服务器: $MCP_URL"

    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AGENT_TOKEN" \
        --connect-timeout 10 \
        -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}},"id":1}' \
        2>/dev/null) || HTTP_CODE="000"

    if [ "$HTTP_CODE" = "200" ]; then
        log_info "MCP 服务器连接成功 (HTTP $HTTP_CODE)"
    elif [ "$HTTP_CODE" = "000" ]; then
        log_error "MCP 服务器无法连接 (网络不通)"
        log_warn "如果在调试模式下，CVM 可能无法连接靶机平台，这是正常的"
    else
        log_warn "MCP 服务器返回 HTTP $HTTP_CODE（可能需要检查 Token 或地址）"
    fi

    # 测试 API 接口
    local API_URL="http://${SERVER_HOST}/api/challenges"
    log_step "测试 API 接口: $API_URL"

    local API_RESPONSE
    API_RESPONSE=$(curl -s \
        -H "Agent-Token: $AGENT_TOKEN" \
        --connect-timeout 10 \
        "$API_URL" 2>/dev/null) || API_RESPONSE=""

    if [ -n "$API_RESPONSE" ]; then
        local API_CODE
        API_CODE=$(echo "$API_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('code','?'))" 2>/dev/null) || API_CODE="?"
        if [ "$API_CODE" = "0" ]; then
            log_info "API 接口连接成功"
            # 显示赛题摘要
            echo "$API_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
print(f\"       当前关卡: {data.get('current_level', '?')}\")
print(f\"       总赛题数: {data.get('total_challenges', '?')}\")
print(f\"       已完成数: {data.get('solved_challenges', '?')}\")
for ch in data.get('challenges', [])[:5]:
    status = '✓' if ch.get('flag_got_count',0) >= ch.get('flag_count',1) else '○'
    print(f\"       {status} {ch['title']} ({ch['difficulty']}) - {ch['total_got_score']}/{ch['total_score']}分\")
total = data.get('total_challenges', 0)
shown = min(5, total)
if total > shown:
    print(f'       ... 还有 {total - shown} 道赛题')
" 2>/dev/null || log_warn "赛题信息解析失败"
        else
            log_warn "API 返回: $API_RESPONSE"
        fi
    else
        log_warn "API 接口无响应（调试模式下可能无法连接靶机平台）"
    fi

    # 测试模型网关
    log_step "测试模型网关: $MODEL_BASE_URL"

    local MODEL_CODE
    MODEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${MODEL_BASE_URL}/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKENHUB_API_KEY" \
        --connect-timeout 10 \
        -d '{"model":"'"$MODEL_ID"'","messages":[{"role":"user","content":"hi"}],"max_tokens":5}' \
        2>/dev/null) || MODEL_CODE="000"

    if [ "$MODEL_CODE" = "200" ]; then
        log_info "模型网关连接成功 (HTTP $MODEL_CODE)"
    elif [ "$MODEL_CODE" = "000" ]; then
        log_error "模型网关无法连接"
    else
        log_warn "模型网关返回 HTTP $MODEL_CODE（请检查 API Key 和 Model ID）"
    fi
}

# ─── 单次运行 ────────────────────────────────────────────────
run_once() {
    log_step "启动 OpenWhale 智能体（单次运行）..."
    echo ""
    uv run openwhale
}

# ─── 自动循环模式 ─────────────────────────────────────────────
run_auto() {
    log_step "启动 OpenWhale 自动循环模式..."
    log_warn "延时遥控：${AUTOPILOT_START_DELAY_SECONDS:-60} 秒后开始首轮执行"
    log_warn "按 Ctrl+C 可中断"
    echo ""
    uv run python scripts/delayed_autopilot.py
}

# ─── 后台运行（答题模式用） ───────────────────────────────────
run_background() {
    log_step "启动 OpenWhale 后台运行模式..."

    local LOG_FILE="logs/autopilot_$(date +%Y%m%d_%H%M%S).log"

    nohup uv run python scripts/delayed_autopilot.py > "$LOG_FILE" 2>&1 &
    local PID=$!

    log_info "后台进程已启动: PID=$PID"
    log_info "日志文件: $LOG_FILE"
    log_info "查看日志: tail -f $LOG_FILE"
    log_info "停止运行: kill $PID"

    echo "$PID" > .openwhale.pid
    log_info "PID 已保存到 .openwhale.pid"
}

# ─── 主逻辑 ──────────────────────────────────────────────────
banner

case "${1:-}" in
    install)
        check_env
        install_deps
        log_info "安装完成！运行 ./start.sh test 测试连通性"
        ;;
    test)
        check_env
        test_connectivity
        ;;
    auto)
        check_env
        install_deps
        test_connectivity
        echo ""
        run_auto
        ;;
    bg|background)
        check_env
        install_deps
        echo ""
        run_background
        ;;
    stop)
        if [ -f .openwhale.pid ]; then
            PID=$(cat .openwhale.pid)
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID"
                log_info "已停止主战场: PID=$PID"
            else
                log_warn "主战场进程 $PID 已不存在"
            fi
            rm -f .openwhale.pid
        fi
        ;;
    status)
        echo ""
        log_step "=== 主战场状态 ==="
        if [ -f .openwhale.pid ]; then
            PID=$(cat .openwhale.pid)
            if kill -0 "$PID" 2>/dev/null; then
                log_info "主战场正在运行: PID=$PID"
                ls -t logs/autopilot_*.log logs/main_*.log 2>/dev/null | head -1 | xargs tail -10 2>/dev/null || echo "  (无日志)"
            else
                log_warn "主战场进程 $PID 已结束"
            fi
        else
            log_warn "主战场未在后台运行"
        fi
        if [ -f data/pentest_notes.json ]; then
            python3 -c "
import json
d = json.load(open('data/pentest_notes.json'))
solved = d.get('solved_flags', {})
challenges = d.get('challenges', {})
print(f'  渗透赛已解题: {len(solved)} 道, 有笔记: {len(challenges)} 道')
for code in solved:
    print(f'    ✓ {code}')
" 2>/dev/null || true
        fi

        ;;
    deploy)
        log_step "开始 CVM 一键部署..."
        bash scripts/deploy_cvm.sh
        ;;
    ""|run)
        check_env
        install_deps
        test_connectivity
        echo ""
        run_once
        ;;
    *)
        echo "用法: $0 [命令]"
        echo ""
        echo "命令:"
        echo "  (无)/run         单次运行智能体（调试模式推荐）"
        echo "  auto             自动循环模式（带延时，答题模式前启动）"
        echo "  bg               后台运行（答题模式推荐）"
        echo "  deploy           CVM 一键部署（安装工具+构建索引+验证环境）"
        echo "  test             仅测试连通性"
        echo "  install          仅安装依赖"
        echo "  status           查看运行状态和结果"
        echo "  stop             停止后台进程"
        exit 1
        ;;
esac
