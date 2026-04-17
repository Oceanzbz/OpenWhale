## OWASP Top 10 快速检查清单

| 编号 | 类别 | 检测方法 |
|------|------|---------|
| A01 | 权限控制缺陷 | 测试越权(IDOR), 目录遍历, 强制浏览(/admin) |
| A02 | 加密失败 | 检查 HTTP(非HTTPS), 弱哈希, 硬编码密钥, 敏感数据明文 |
| A03 | 注入 | SQL/NoSQL/OS命令/LDAP/SSTI/XSS — 所有输入点都测试 |
| A04 | 不安全设计 | 逻辑缺陷, 业务流程绕过, 竞态条件 |
| A05 | 安全配置错误 | 默认凭据, 错误页面泄露, Debug模式 |
| A06 | 脆弱组件 | 检查中间件版本, nuclei扫CVE, searchsploit |
| A07 | 认证缺陷 | 弱口令, JWT缺陷, Session固定, 密码重置逻辑 |
| A08 | 数据完整性 | 反序列化, 依赖混淆, 不安全的CI/CD |
| A09 | 日志监控不足 | 暴露日志文件(/logs/, /debug/), 错误信息泄露 |
| A10 | SSRF | URL参数/Webhook/回调/import/fetch/proxy中测试: http://127.0.0.1, file:///flag, gopher, IP变体, 内网服务探测 |
