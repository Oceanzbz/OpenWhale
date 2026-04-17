#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# OpenWhale 安全工具一键安装脚本
# 运行方式: bash scripts/setup_tools.sh [--all|--core|--go|--pip|--git]
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

TOOLS_DIR="/opt/tools"
MODE="${1:-core}"

# ── 环境检查 ──────────────────────────────────────────────────
check_env() {
    info "检查环境..."
    
    if command -v python3 &>/dev/null; then
        info "Python3: $(python3 --version)"
    else
        error "Python3 未安装"; exit 1
    fi
    
    if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
        info "pip: OK"
    else
        warn "pip 未安装, 尝试安装..."
        python3 -m ensurepip --upgrade 2>/dev/null || true
    fi
    
    if command -v go &>/dev/null; then
        info "Go: $(go version)"
        export PATH=$PATH:$(go env GOPATH 2>/dev/null)/bin
    else
        warn "Go 未安装, Go工具将被跳过"
    fi
    
    if command -v git &>/dev/null; then
        info "Git: $(git --version)"
    else
        error "Git 未安装"; exit 1
    fi
    
    sudo mkdir -p "$TOOLS_DIR" 2>/dev/null || mkdir -p "$TOOLS_DIR" 2>/dev/null || {
        TOOLS_DIR="$HOME/tools"
        mkdir -p "$TOOLS_DIR"
        warn "无法创建 /opt/tools, 使用 $TOOLS_DIR"
    }
}

# ── pip 工具安装 ──────────────────────────────────────────────
install_pip_tools() {
    info "=== 安装 Python 工具 ==="
    
    local tools=(
        "sqlmap"
        "dirsearch"
        "flask-unsign[wordlist]"
        "git-dumper"
        "fenjing"
        "pwntools"
    )
    
    for tool in "${tools[@]}"; do
        name=$(echo "$tool" | sed 's/\[.*//') 
        if pip3 show "$name" &>/dev/null 2>&1; then
            info "  $name 已安装"
        else
            info "  安装 $name ..."
            pip3 install "$tool" --quiet 2>/dev/null && info "  $name ✅" || warn "  $name 安装失败"
        fi
    done
}

# ── Go 工具安装 ──────────────────────────────────────────────
install_go_tools() {
    if ! command -v go &>/dev/null; then
        warn "Go 未安装, 跳过 Go 工具"
        return
    fi
    
    info "=== 安装 Go 工具 ==="
    export PATH=$PATH:$(go env GOPATH)/bin
    
    declare -A go_tools=(
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["afrog"]="github.com/zan8in/afrog/v3/cmd/afrog@latest"
        ["chisel"]="github.com/jpillora/chisel@latest"
    )
    
    for name in "${!go_tools[@]}"; do
        if command -v "$name" &>/dev/null; then
            info "  $name 已安装"
        else
            info "  安装 $name ..."
            go install -v "${go_tools[$name]}" 2>/dev/null && info "  $name ✅" || warn "  $name 安装失败"
        fi
    done
    
    if command -v nuclei &>/dev/null; then
        info "  更新 Nuclei 模板..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi
}

# ── Git 工具安装 ──────────────────────────────────────────────
install_git_tools() {
    info "=== 安装 Git 工具 ==="
    
    declare -A git_tools=(
        ["SSTImap"]="https://github.com/vladko312/SSTImap.git"
        ["jwt_tool"]="https://github.com/ticarpi/jwt_tool.git"
        ["Gopherus"]="https://github.com/tarunkant/Gopherus.git"
        ["redis-rogue-server"]="https://github.com/n0b0dyCN/redis-rogue-server.git"
        ["PayloadsAllTheThings"]="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    )
    
    for name in "${!git_tools[@]}"; do
        target="$TOOLS_DIR/$name"
        if [ -d "$target" ]; then
            info "  $name 已存在"
        else
            info "  克隆 $name ..."
            git clone --depth 1 "${git_tools[$name]}" "$target" 2>/dev/null && info "  $name ✅" || warn "  $name 克隆失败"
            if [ -f "$target/requirements.txt" ]; then
                pip3 install -r "$target/requirements.txt" --quiet 2>/dev/null || true
            fi
        fi
    done
    
    # SecLists
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "$TOOLS_DIR/SecLists" ]; then
        info "  克隆 SecLists (精简版)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TOOLS_DIR/SecLists" 2>/dev/null && {
            info "  SecLists ✅"
            ln -sf "$TOOLS_DIR/SecLists" /usr/share/seclists 2>/dev/null || true
        } || warn "  SecLists 克隆失败"
    else
        info "  SecLists 已存在"
    fi
}

# ── 二进制工具安装 ────────────────────────────────────────────
install_binary_tools() {
    info "=== 安装二进制工具 ==="
    
    # ysoserial
    if [ ! -f "$TOOLS_DIR/ysoserial.jar" ]; then
        info "  下载 ysoserial..."
        wget -q "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
            -O "$TOOLS_DIR/ysoserial.jar" 2>/dev/null && info "  ysoserial ✅" || warn "  ysoserial 下载失败"
    else
        info "  ysoserial 已存在"
    fi
    
    # JNDIExploit
    if [ ! -f "$TOOLS_DIR/JNDIExploit"*.jar ] 2>/dev/null; then
        info "  下载 JNDIExploit..."
        wget -q "https://github.com/Mr-xn/JNDIExploit-1/releases/download/v1.4/JNDIExploit.v1.4.zip" \
            -O /tmp/jndi.zip 2>/dev/null && \
        unzip -o /tmp/jndi.zip -d "$TOOLS_DIR/" 2>/dev/null && \
        rm /tmp/jndi.zip && \
        info "  JNDIExploit ✅" || warn "  JNDIExploit 下载失败"
    else
        info "  JNDIExploit 已存在"
    fi
}

# ── 系统工具安装 ──────────────────────────────────────────────
install_system_tools() {
    info "=== 安装系统工具 ==="
    
    for tool in nmap curl wget unzip; do
        if command -v "$tool" &>/dev/null; then
            info "  $tool 已安装"
        else
            info "  安装 $tool ..."
            if command -v brew &>/dev/null; then
                brew install "$tool" 2>/dev/null || true
            elif command -v apt &>/dev/null; then
                sudo apt install -y "$tool" 2>/dev/null || true
            fi
        fi
    done
}

# ── 状态报告 ─────────────────────────────────────────────────
print_status() {
    echo ""
    info "=== 安装状态报告 ==="
    
    local tools=("nuclei" "httpx" "naabu" "subfinder" "ffuf" "afrog" "chisel" \
                 "sqlmap" "dirsearch" "flask-unsign" "git-dumper" "fenjing" \
                 "nmap" "hashcat" "john")
    
    for t in "${tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $t"
        else
            echo -e "  ${RED}❌${NC} $t"
        fi
    done
    
    local git_tools=("SSTImap" "jwt_tool" "Gopherus" "redis-rogue-server" "PayloadsAllTheThings" "SecLists")
    for t in "${git_tools[@]}"; do
        if [ -d "$TOOLS_DIR/$t" ]; then
            echo -e "  ${GREEN}✅${NC} $t ($TOOLS_DIR/$t)"
        else
            echo -e "  ${RED}❌${NC} $t"
        fi
    done
    
    if [ -f "$TOOLS_DIR/ysoserial.jar" ]; then
        echo -e "  ${GREEN}✅${NC} ysoserial ($TOOLS_DIR/ysoserial.jar)"
    else
        echo -e "  ${RED}❌${NC} ysoserial"
    fi
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    echo "═══════════════════════════════════════"
    echo "  OpenWhale 安全工具安装器"
    echo "  工具目录: $TOOLS_DIR"
    echo "  模式: $MODE"
    echo "═══════════════════════════════════════"
    echo ""
    
    check_env
    
    case "$MODE" in
        --all|all)
            install_system_tools
            install_pip_tools
            install_go_tools
            install_git_tools
            install_binary_tools
            ;;
        --core|core)
            install_pip_tools
            install_go_tools
            ;;
        --pip|pip)
            install_pip_tools
            ;;
        --go|go)
            install_go_tools
            ;;
        --git|git)
            install_git_tools
            install_binary_tools
            ;;
        --status|status)
            ;;
        *)
            echo "用法: $0 [--all|--core|--pip|--go|--git|--status]"
            echo "  --all    安装所有工具"
            echo "  --core   安装pip+go核心工具(默认)"
            echo "  --pip    仅安装Python工具"
            echo "  --go     仅安装Go工具"
            echo "  --git    仅安装Git工具+二进制"
            echo "  --status 仅显示状态"
            exit 0
            ;;
    esac
    
    print_status
}

main "$@"
