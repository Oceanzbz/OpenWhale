## 可用工具

- **MCP 赛事工具**：list_challenges / start_challenge / submit_flag / view_hint / stop_challenge
- **Bash 工具**：执行命令行工具，★ 优先用 Bash(curl/python3) 手动操作
  - 需要写脚本时直接用 python3 -c "..." 或写临时文件
- **笔记工具**：save_note / read_notes（持久化发现，跨运行复用）
- **缓存工具**：save_recon / read_recon（缓存侦察结果，避免重复）
- **知识库工具**：search_vuln_kb / get_payloads（需要特定漏洞payload时使用）
- **POC知识库**：search_poc_kb / read_poc_file（识别到具体产品/版本后使用）

## CVM 已安装的渗透工具（可直接在Bash中调用）

### 扫描/枚举
- `nmap` — 端口扫描/服务识别（加 `-T4 --max-retries 1 --host-timeout 30s`）
- `masscan` — 大范围快速端口扫描（`sudo masscan -p1-65535 TARGET --rate=1000`）
- `ffuf` — Web模糊测试/目录爆破（`ffuf -u URL/FUZZ -w wordlist -mc 200,301,302,403`）
- `gobuster` — 目录/DNS/vhost爆破
- `nikto` — Web服务器漏洞扫描
- `dig` / `whois` — DNS/域名信息查询

### 漏洞利用
- `sqlmap` — SQL注入自动化（`sqlmap -u "URL?id=1" --batch --level=3`）
- `hydra` — 暴力破解（`hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form`）

### 内网渗透/隧道
- `chisel` — HTTP隧道端口转发（`chisel server -p 8888 --reverse` / `chisel client SERVER:8888 R:socks`）
- `frpc`/`frps` — 反向代理隧道（配置文件方式建立SOCKS代理）
- `proxychains4` — 强制TCP流量通过代理（`proxychains4 curl http://internal:8080/`）
- `socat` — 多功能中继/端口转发（`socat TCP-LISTEN:4444,fork TCP:internal:80`）

### 数据库客户端
- `redis-cli` — Redis客户端（`redis-cli -h TARGET -p 6379`）
- `mysql` — MySQL客户端（`mysql -h TARGET -u root -p`）

### 网络工具
- `nc`/`netcat` — 网络连接/监听（`nc -lvp 4444`）
- `curl` — HTTP请求（★ 所有请求加 `-m 10` 超时）
- `sshpass` — 自动SSH密码登录

### Python库（可在python3脚本中import）
- `requests` — HTTP请求库（★ 加 timeout=10）
- `paramiko` — SSH/SFTP客户端（连接内网SSH服务）
- `lxml` — XML/HTML解析（XXE payload构造、HTML数据提取）
- `impacket` — Windows协议工具包（系统python3可用：SMB/WMI/Kerberos）
