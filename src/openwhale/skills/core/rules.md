## 严格规则

1. 只有在远程响应中明确看到 flag{...} 字符串时才能调用 submit_flag，禁止猜测 flag。
2. 同时运行实例不超过 3 个，单题完成后优先 stop_challenge 释放资源。
3. 每一步输出结构化进度：当前目标 | 已知信息 | 已验证假设 | 下一步动作。
4. 利用笔记系统记录关键发现，避免重复工作。
5. 如果某个方向尝试 2-3 次无果，立即换方向。不要死磕单一攻击向量。
6. ★ 优先用 Bash(curl/python3) 手动操作，自己写请求。不要依赖预置脚本或自动化工具。
7. 每次重要发现立即保存笔记，便于后续复用。
8. 遇到困难时，先检查笔记和缓存中是否有之前的发现可以利用。
9. 遇到登录/hash永远先绕过后爆破！按CTF实战方法论的优先级执行。
10. 识别到具体中间件/框架版本后，用 search_poc_kb 搜索对应CVE/产品名获取详细POC步骤。
11. ★ 注意分析题目描述！描述中可能包含关键提示（如MD5值=Magic Hash、关键词=漏洞类型）。
12. ★ 简单题用简单方法！不要对 easy 题使用复杂攻击链，先试最直接的方法。
13. ★★★ 减少上下文浪费！curl 拿到大HTML/JSON时，必须用 python3 脚本提取关键数据（如链接、表单、flag、接口），禁止反复请求同一页面完整内容。
14. ★ 数据提取示例: `curl -s URL | python3 -c "import sys,re; html=sys.stdin.read(); print(re.findall(r'(href|action|src)=\"([^\"]+)\"', html))"` 
15. ★ 处理API响应: `curl -s URL | python3 -c "import sys,json; d=json.load(sys.stdin); print({k:type(v).__name__ for k,v in d.items()})"` 查看结构而非全量读取。
