#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# OpenWhale CVM 一键部署脚本
# 在调试模式（有公网）时运行一次，部署完成后切答题模式
# 用法: bash scripts/deploy_cvm.sh
# ═══════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

log() { echo ""; echo "════════════════════════════════════════"; echo " $1"; echo "════════════════════════════════════════"; }

cd "$PROJECT_DIR"

log "Step 1/6: 安装 Python 依赖 (uv)"
if command -v uv &>/dev/null; then
    uv sync 2>/dev/null || uv pip install -e . 2>/dev/null || pip3 install -e . 2>/dev/null
    echo "✓ Python 依赖已安装"
else
    pip3 install -e . 2>/dev/null || echo "⚠ pip install 失败, 请手动安装"
fi

log "Step 2/6: 安装渗透工具"
bash scripts/install_tools.sh

log "Step 3/6: 验证工具完整性"
MISSING=0
for tool in python3 curl; do
    if ! command -v "$tool" &>/dev/null; then
        echo "✗ 缺少必要工具: $tool"
        MISSING=$((MISSING+1))
    fi
done
for f in tools/wordlists/common_dirs.txt; do
    if [ ! -f "$f" ]; then
        echo "✗ 缺少文件: $f"
        MISSING=$((MISSING+1))
    fi
done
if [ $MISSING -eq 0 ]; then
    echo "✓ 核心工具完整"
else
    echo "⚠ 有 $MISSING 项缺失, 但可能不影响基本功能"
fi

log "Step 4/6: 构建 POC 索引缓存"
python3 -c "
import sys, types
logger_mod = types.ModuleType('loguru')
class FL:
    def info(self, *a, **k): print('[INFO]', *a)
    def warning(self, *a, **k): pass
    def debug(self, *a, **k): pass
logger_mod.logger = FL()
sys.modules['loguru'] = logger_mod
spec = __import__('importlib.util', fromlist=['util']).spec_from_file_location('poc_index', 'src/openwhale/util/poc_index.py')
mod = __import__('importlib.util', fromlist=['util']).module_from_spec(spec)
spec.loader.exec_module(mod)
idx = mod.PocIndex(cache_path='data/poc_index_cache.json')
print(idx.build())
" 2>/dev/null || echo "⚠ POC 索引构建跳过 (非关键)"

log "Step 5/6: 连通性测试"
if [ -f scripts/quick_test.py ]; then
    python3 scripts/quick_test.py 2>&1 | tail -20
else
    echo "⚠ quick_test.py 不存在, 跳过"
fi

log "Step 6/6: 部署状态报告"
echo ""
echo "项目目录: $PROJECT_DIR"
echo "利用脚本:"
ls -1 scripts/exploits/*.py 2>/dev/null | while read f; do echo "  ✓ $(basename "$f")"; done
echo ""
echo "Java 工具:"
ls -1 tools/*.jar 2>/dev/null | while read f; do echo "  ✓ $(basename "$f") ($(du -sh "$f" | cut -f1))"; done || echo "  (无 .jar 文件)"
echo ""
echo "知识库:"
if [ -d kb ]; then
    echo "  ✓ POC 知识库: $(find kb -name '*.md' 2>/dev/null | wc -l | tr -d ' ') 篇"
else
    echo "  ✗ kb/ 目录不存在"
fi
echo ""
echo "环境变量: $(head -1 .env 2>/dev/null || echo '(无 .env)')"
echo ""

echo "════════════════════════════════════════"
echo " 部署完成! 下一步操作:"
echo "════════════════════════════════════════"
echo ""
echo "  1. 调试模式测试:  ./start.sh run"
echo "  2. 后台启动:      ./start.sh bg"
echo "  3. 切答题模式后:  Agent 自动运行"
echo ""
