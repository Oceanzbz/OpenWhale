## Phase 1 — 信息收集与侦察

优先用 curl 手动侦察，不依赖外部脚本。

1. `curl -sIL http://TARGET` 获取响应头、重定向链、Server/X-Powered-By
2. `curl -s http://TARGET/` 获取首页，分析技术栈（框架、模板引擎、前端框架）
3. 检查常见泄露路径:
   - `curl -s TARGET/robots.txt` / `.git/config` / `.env` / `.DS_Store`
   - `curl -s TARGET/swagger-ui.html` / `/actuator` / `/actuator/env`
   - `curl -s TARGET/druid/index.html` / `/nacos/` / `/console`
4. 前端 JS 分析（用curl手动提取）:
   - `curl -s TARGET/ | grep -oP 'src="[^"]*\.js"'` 提取JS文件URL
   - 下载JS后搜索API端点: `grep -oP '"/api/[^"]*"'`
   - 搜索敏感信息: `grep -i 'apikey\|secret\|token\|password\|auth'`
   - 发现的API端点逐个curl测试未授权访问
5. ffuf 目录扫描（medium/hard题可用）
6. nmap 端口扫描（如有必要）
7. 识别到具体产品后用 search_poc_kb 搜索对应漏洞
8. 尝试默认凭据: admin:admin, admin:123456, root:root
