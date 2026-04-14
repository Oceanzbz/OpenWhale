#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# OpenWhale 渗透工具离线安装脚本
# 在调试模式（有公网）时运行，安装所有比赛所需工具
# 用法: bash scripts/install_tools.sh
# ═══════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_DIR/tools"
WORDLIST_DIR="$TOOLS_DIR/wordlists"

mkdir -p "$TOOLS_DIR" "$WORDLIST_DIR" "$PROJECT_DIR/logs"

log() { echo "[$(date '+%H:%M:%S')] $1"; }
ok()  { echo "[$(date '+%H:%M:%S')] ✓ $1"; }
warn(){ echo "[$(date '+%H:%M:%S')] ⚠ $1"; }
err() { echo "[$(date '+%H:%M:%S')] ✗ $1"; }

log "=== OpenWhale 渗透工具安装 ==="
log "工具目录: $TOOLS_DIR"
echo ""

FAIL_COUNT=0

# ── 1. Java 环境检查 ──────────────────────────────────────────
log "[1/9] 检查 Java 环境..."
if command -v java &>/dev/null; then
    JAVA_VER=$(java -version 2>&1 | head -1)
    ok "Java: $JAVA_VER"
else
    warn "Java 未安装, 尝试安装..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq default-jre 2>/dev/null && ok "Java 安装完成" || { err "Java 安装失败"; FAIL_COUNT=$((FAIL_COUNT+1)); }
    elif command -v yum &>/dev/null; then
        sudo yum install -y -q java-11-openjdk 2>/dev/null && ok "Java 安装完成" || { err "Java 安装失败"; FAIL_COUNT=$((FAIL_COUNT+1)); }
    else
        err "无法自动安装 Java, 请手动安装 OpenJDK 11+"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 2. ysoserial (Java 反序列化) ──────────────────────────────
log "[2/9] 准备 ysoserial.jar..."
if [ -f "$TOOLS_DIR/ysoserial.jar" ] || [ -f "$TOOLS_DIR/ysoserial-all.jar" ]; then
    ok "ysoserial 已存在"
else
    curl -sL --connect-timeout 15 -o "$TOOLS_DIR/ysoserial-all.jar" \
        "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" 2>/dev/null
    if [ -f "$TOOLS_DIR/ysoserial-all.jar" ] && [ -s "$TOOLS_DIR/ysoserial-all.jar" ]; then
        ln -sf ysoserial-all.jar "$TOOLS_DIR/ysoserial.jar"
        ok "ysoserial 下载完成 ($(du -sh "$TOOLS_DIR/ysoserial-all.jar" | cut -f1))"
    else
        rm -f "$TOOLS_DIR/ysoserial-all.jar"
        err "ysoserial 下载失败, 请手动下载到 $TOOLS_DIR/ysoserial.jar"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 3. JNDIExploit (Log4j/Fastjson/Shiro JNDI利用) ──────────
log "[3/9] 准备 JNDIExploit..."
if [ -f "$TOOLS_DIR/JNDIExploit.jar" ] || [ -f "$TOOLS_DIR/JNDIExploit-1.4-SNAPSHOT.jar" ]; then
    ok "JNDIExploit 已存在"
else
    curl -sL --connect-timeout 15 -o /tmp/jndi.zip \
        "https://github.com/WhiteHSBG/JNDIExploit/releases/download/v1.4/JNDIExploit.v1.4.zip" 2>/dev/null
    if [ -f /tmp/jndi.zip ] && [ -s /tmp/jndi.zip ]; then
        unzip -qo /tmp/jndi.zip -d "$TOOLS_DIR/" 2>/dev/null
        # 找到解压出来的 jar 文件并创建链接
        JNDI_JAR=$(find "$TOOLS_DIR" -name "JNDIExploit*.jar" -type f 2>/dev/null | head -1)
        if [ -n "$JNDI_JAR" ]; then
            ln -sf "$(basename "$JNDI_JAR")" "$TOOLS_DIR/JNDIExploit.jar" 2>/dev/null || true
            ok "JNDIExploit 下载完成"
        else
            err "JNDIExploit 解压失败"
            FAIL_COUNT=$((FAIL_COUNT+1))
        fi
        rm -f /tmp/jndi.zip
    else
        err "JNDIExploit 下载失败"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 4. Python 渗透库 ──────────────────────────────────────────
log "[4/9] 安装 Python 渗透库..."
pip3 install --quiet --no-warn-script-location \
    pycryptodome requests httpx PyJWT beautifulsoup4 lxml pyyaml paramiko 2>/dev/null \
    && ok "Python 库安装完成" \
    || { warn "部分 Python 库安装失败, 非关键"; }

# ── 5. Nuclei ─────────────────────────────────────────────────
log "[5/9] 准备 nuclei..."
if command -v nuclei &>/dev/null; then
    ok "nuclei 已安装: $(nuclei --version 2>&1 | head -1)"
else
    ARCH=$(uname -m); OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$ARCH" in x86_64|amd64) ARCH="amd64";; aarch64|arm64) ARCH="arm64";; esac
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${OS}_${ARCH}.zip"
    curl -sL --connect-timeout 15 -o /tmp/nuclei.zip "$NUCLEI_URL" 2>/dev/null
    if [ -f /tmp/nuclei.zip ] && [ -s /tmp/nuclei.zip ]; then
        unzip -qo /tmp/nuclei.zip nuclei -d /usr/local/bin/ 2>/dev/null || unzip -qo /tmp/nuclei.zip nuclei -d "$TOOLS_DIR/" 2>/dev/null
        chmod +x /usr/local/bin/nuclei 2>/dev/null || chmod +x "$TOOLS_DIR/nuclei" 2>/dev/null
        ok "nuclei 安装完成"
        rm -f /tmp/nuclei.zip
        nuclei -update-templates -silent 2>/dev/null && ok "nuclei 模板更新完成" || warn "nuclei 模板更新失败"
    else
        err "nuclei 下载失败"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 6. ffuf ───────────────────────────────────────────────────
log "[6/9] 准备 ffuf..."
if command -v ffuf &>/dev/null; then
    ok "ffuf 已安装"
else
    ARCH=$(uname -m); OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$ARCH" in x86_64|amd64) ARCH="amd64";; aarch64|arm64) ARCH="arm64";; esac
    FFUF_URL="https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${OS}_${ARCH}.tar.gz"
    curl -sL --connect-timeout 15 -o /tmp/ffuf.tar.gz "$FFUF_URL" 2>/dev/null
    if [ -f /tmp/ffuf.tar.gz ] && [ -s /tmp/ffuf.tar.gz ]; then
        tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf 2>/dev/null || tar xzf /tmp/ffuf.tar.gz -C "$TOOLS_DIR/" ffuf 2>/dev/null
        chmod +x /usr/local/bin/ffuf 2>/dev/null || chmod +x "$TOOLS_DIR/ffuf" 2>/dev/null
        ok "ffuf 安装完成"
        rm -f /tmp/ffuf.tar.gz
    else
        err "ffuf 下载失败"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 7. dirsearch + sqlmap ─────────────────────────────────────
log "[7/9] 准备 dirsearch + sqlmap..."
pip3 install --quiet dirsearch 2>/dev/null && ok "dirsearch 安装完成" || warn "dirsearch 安装失败"
if ! command -v sqlmap &>/dev/null; then
    pip3 install --quiet sqlmap 2>/dev/null && ok "sqlmap 安装完成" || warn "sqlmap 安装失败"
else
    ok "sqlmap 已安装"
fi

# ── 8. 系统工具 ───────────────────────────────────────────────
log "[8/9] 检查系统工具..."
for cmd in nmap curl wget jq; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd 已安装"
    else
        warn "$cmd 未安装, 尝试安装..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y -qq "$cmd" 2>/dev/null && ok "$cmd 安装完成" || warn "$cmd 安装失败"
        elif command -v yum &>/dev/null; then
            sudo yum install -y -q "$cmd" 2>/dev/null && ok "$cmd 安装完成" || warn "$cmd 安装失败"
        fi
    fi
done

# ── 9. 字典文件 ───────────────────────────────────────────────
log "[9/9] 准备字典文件..."

cat > "$WORDLIST_DIR/common_dirs.txt" << 'DIRS_EOF'
admin
login
api
api/v1
api/v2
swagger-ui.html
swagger-ui/
v2/api-docs
v3/api-docs
swagger.json
openapi.json
graphql
graphiql
actuator
actuator/env
actuator/health
actuator/info
actuator/heapdump
actuator/mappings
actuator/configprops
actuator/gateway/routes
actuator/beans
actuator/trace
console
manager
manager/html
manager/status
dashboard
config
system
monitor
debug
test
backup
upload
download
static
assets
dist
build
public
favicon.ico
robots.txt
sitemap.xml
.env
.git/config
.git/HEAD
.DS_Store
.svn/entries
WEB-INF/web.xml
META-INF/MANIFEST.MF
phpinfo.php
info.php
test.php
server-status
server-info
druid/index.html
druid/
nacos/
nacos/v1/auth/users
xxl-job-admin
jenkins
grafana
kibana
phpmyadmin
adminer
solr/admin/
elasticsearch
elasticsearch/_cat
zookeeper
dubbo
spring
index.action
login.action
index.do
login.do
struts
user
users
member
account
profile
register
signup
signin
logout
forgot
reset
password
settings
status
health
ping
version
info
about
help
docs
doc
documentation
README.md
CHANGELOG.md
package.json
composer.json
wp-json/
xmlrpc.php
wp-admin/
wp-login.php
wp-content/
administrator/
admin.php
login.php
config.php
database
db
sql
data
log
logs
error
errors
tmp
temp
cache
bak
backup.zip
backup.tar.gz
backup.sql
dump.sql
db.sql
1.txt
test.txt
flag
flag.txt
secret
crossdomain.xml
clientaccesspolicy.xml
.well-known/openid-configuration
.htaccess
.htpasswd
web.config
app.config
Dockerfile
docker-compose.yml
.dockerenv
DIRS_EOF

cat > "$WORDLIST_DIR/common_passwords.txt" << 'PWD_EOF'
admin
123456
password
12345678
admin123
root
test
test123
admin888
admin666
123456789
1234567890
admin1
qwerty
abc123
letmein
monkey
master
dragon
login
princess
123123
welcome
shadow
sunshine
trustno1
iloveyou
batman
654321
superman
qwerty123
1q2w3e4r
passw0rd
P@ssw0rd
admin@123
root123
toor
guest
default
manager
operator
p@ssword
changeme
PWD_EOF

cat > "$WORDLIST_DIR/common_users.txt" << 'USR_EOF'
admin
root
test
guest
user
administrator
manager
operator
tomcat
jenkins
nacos
druid
system
oracle
postgres
mysql
redis
www
www-data
nobody
deploy
devops
git
svn
backup
monitor
USR_EOF

ok "字典文件已准备 ($(wc -l < "$WORDLIST_DIR/common_dirs.txt") 目录 / $(wc -l < "$WORDLIST_DIR/common_passwords.txt") 密码 / $(wc -l < "$WORDLIST_DIR/common_users.txt") 用户名)"

# ── 汇总 ──────────────────────────────────────────────────────
echo ""
log "=== 安装完成 ==="
echo ""
log "工具清单:"
for f in "$TOOLS_DIR"/*.jar; do [ -f "$f" ] && echo "  ✓ $(basename "$f") ($(du -sh "$f" | cut -f1))"; done
for cmd in nuclei ffuf dirsearch sqlmap nmap curl jq python3 java; do
    if command -v "$cmd" &>/dev/null; then
        echo "  ✓ $cmd: $(command -v "$cmd")"
    elif [ -f "$TOOLS_DIR/$cmd" ]; then
        echo "  ✓ $cmd: $TOOLS_DIR/$cmd"
    else
        echo "  ✗ $cmd: 未安装"
    fi
done
echo ""
log "字典: $WORDLIST_DIR/"
ls -la "$WORDLIST_DIR/" 2>/dev/null
echo ""
log "利用脚本:"
ls -1 "$SCRIPT_DIR/exploits/"*.py 2>/dev/null | while read f; do echo "  ✓ $(basename "$f")"; done
echo ""

if [ $FAIL_COUNT -gt 0 ]; then
    warn "有 $FAIL_COUNT 项安装失败, 请检查上方日志"
else
    ok "全部安装成功!"
fi
