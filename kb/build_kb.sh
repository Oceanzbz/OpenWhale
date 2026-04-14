#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# OpenWhale POC 知识库打包脚本
# 从本地多个知识源复制 .md 文件到 kb/ 下的分类目录
# 打包后上传到 CVM 服务器的项目目录即可
# ═══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KB_DIR="$SCRIPT_DIR"

echo "=== OpenWhale POC 知识库构建 ==="
echo "目标目录: $KB_DIR"
echo ""

# 清理旧数据（保留脚本自身）
for d in awesome-poc poc-main hacktricks pentest-note java-security ctf-writeup pentest-writeup personal-notes; do
    rm -rf "$KB_DIR/$d"
done

# ── 1. Awesome-POC (P0 最高优先级, ~808 MD) ──
SRC="/Volumes/T7mac/POC/Awesome-POC-1.0"
if [ -d "$SRC" ]; then
    echo "[1/8] 复制 Awesome-POC ..."
    mkdir -p "$KB_DIR/awesome-poc"
    find "$SRC" -name '*.md' -not -path '*/node_modules/*' -not -path '*/.git/*' | while read f; do
        # 保留一级子目录结构
        rel="${f#$SRC/}"
        dir="$KB_DIR/awesome-poc/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/awesome-poc" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[1/8] 跳过 Awesome-POC (路径不存在: $SRC)"
fi

# ── 2. POC-main (P0 最高优先级, ~2477 MD) ──
SRC="/Volumes/T7mac/POC/POC-main/wpoc"
if [ -d "$SRC" ]; then
    echo "[2/8] 复制 POC-main ..."
    mkdir -p "$KB_DIR/poc-main"
    find "$SRC" -name '*.md' -not -path '*/node_modules/*' -not -path '*/.git/*' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/poc-main/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/poc-main" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[2/8] 跳过 POC-main (路径不存在: $SRC)"
fi

# ── 3. HackTricks (P1, ~960 MD) ──
SRC="/Volumes/T7mac/POC/hacktricks/src"
if [ -d "$SRC" ]; then
    echo "[3/8] 复制 HackTricks ..."
    mkdir -p "$KB_DIR/hacktricks"
    find "$SRC" -name '*.md' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/theme/*' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/hacktricks/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/hacktricks" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[3/8] 跳过 HackTricks (路径不存在: $SRC)"
fi

# ── 4. Pentest_Note (P2, ~676 MD) ──
SRC="/Volumes/T7mac/POC/Pentest_Note-master/wiki"
if [ -d "$SRC" ]; then
    echo "[4/8] 复制 Pentest_Note ..."
    mkdir -p "$KB_DIR/pentest-note"
    find "$SRC" -name '*.md' -not -path '*/node_modules/*' -not -path '*/.git/*' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/pentest-note/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/pentest-note" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[4/8] 跳过 Pentest_Note (路径不存在: $SRC)"
fi

# ── 5. Java 安全博文 (P1, ~36 MD) ──
SRC="/Users/ocean/Cybersecurity/Blog/source/_posts/Java安全"
if [ -d "$SRC" ]; then
    echo "[5/8] 复制 Java安全 ..."
    mkdir -p "$KB_DIR/java-security"
    find "$SRC" -name '*.md' | while read f; do
        cp "$f" "$KB_DIR/java-security/"
    done
    echo "   $(find "$KB_DIR/java-security" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[5/8] 跳过 Java安全 (路径不存在: $SRC)"
fi

# ── 6. CTF Writeup (P1, ~8 MD) ──
SRC="/Users/ocean/Cybersecurity/Blog/source/_posts/CTF"
if [ -d "$SRC" ]; then
    echo "[6/8] 复制 CTF Writeup ..."
    mkdir -p "$KB_DIR/ctf-writeup"
    find "$SRC" -name '*.md' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/ctf-writeup/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/ctf-writeup" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[6/8] 跳过 CTF Writeup (路径不存在: $SRC)"
fi

# ── 7. 攻防渗透博文 (P2, ~57 MD) ──
SRC="/Users/ocean/Cybersecurity/Blog/source/_posts/攻防渗透"
if [ -d "$SRC" ]; then
    echo "[7/8] 复制 攻防渗透 ..."
    mkdir -p "$KB_DIR/pentest-writeup"
    find "$SRC" -name '*.md' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/pentest-writeup/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/pentest-writeup" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[7/8] 跳过 攻防渗透 (路径不存在: $SRC)"
fi

# ── 8. 个人笔记精选 (P2, 只取核心目录避免重复) ──
SRC="/Users/ocean/Cybersecurity/笔记"
if [ -d "$SRC" ]; then
    echo "[8/8] 复制 个人笔记(精选) ..."
    mkdir -p "$KB_DIR/personal-notes"
    # 只复制一级子目录中的 .md，排除已有副本(PayloadsAllTheThings/Pentest_Note等)
    find "$SRC" -maxdepth 3 -name '*.md' \
        -not -path '*/PayloadsAllTheThings*' \
        -not -path '*/Pentest_Note*' \
        -not -path '*/The-Hacker-Recipes*' \
        -not -path '*/node_modules/*' \
        -not -path '*/.git/*' \
        -not -path '*/.obsidian/*' | while read f; do
        rel="${f#$SRC/}"
        dir="$KB_DIR/personal-notes/$(dirname "$rel")"
        mkdir -p "$dir"
        cp "$f" "$dir/"
    done
    echo "   $(find "$KB_DIR/personal-notes" -name '*.md' | wc -l | tr -d ' ') 篇"
else
    echo "[8/8] 跳过 个人笔记 (路径不存在: $SRC)"
fi

echo ""
echo "=== 构建完成 ==="
TOTAL=$(find "$KB_DIR" -name '*.md' | wc -l | tr -d ' ')
SIZE=$(du -sh "$KB_DIR" | cut -f1)
echo "总计: $TOTAL 篇 MD 文档, 磁盘占用: $SIZE"
echo ""
echo "打包命令:"
echo "  cd $(dirname "$KB_DIR") && tar czf kb.tar.gz kb/"
echo ""
echo "上传到 CVM 后解压到项目根目录:"
echo "  cd /path/to/OpenWhale-main && tar xzf kb.tar.gz"
