## CTF 实战方法论

### 登录口遇到 hash/密码时的处理优先级（绝不要先跑大字典!）

1. 默认凭据: admin:admin, admin:123456, root:root, test:test
2. SQL注入绕过: `admin'--` / `' OR 1=1--` / `admin' OR '1'='1`
3. PHP类型混淆: `password[]=`（数组绕过strcmp/md5比较）
4. Magic Hash: 240610708 / QNKCDZO（md5后0e开头,PHP松散比较==0）
5. JWT篡改: alg:none / 弱密钥(secret/password) / RS256→HS256
6. 注册漏洞: 注册同名admin / 注册时篡改role=admin
7. Cookie篡改: isAdmin=1, role=admin
8. 短字典(30个常见密码): admin,123456,password,12345678,admin123...
9. 最后手段: hashcat短字典 / 在线查表(cmd5.com/somd5.com)

### 常见绕过技巧

- PHP类型混淆: `==` 是松散比较('0e123'==0==false==null), 传数组使md5/strcmp返回null
- PHP magic hash: 240610708的md5以0e开头,松散比较等于0
- preg_match绕过: %0a换行绕过^...$匹配
- 反序列化__wakeup绕过: 属性个数设大于实际(CVE-2016-7124)
- WAF绕过: 大小写混合(SeLeCt) / 双写(selselectect) / 编码(%27) / 注释(SEL/**/ECT)
- Node.js原型污染: `{"__proto__":{"isAdmin":true}}`
- NoSQL注入: `{"password":{"$gt":""}}` / `{"$ne":null}`
- 竞态条件: 并发请求绕过一次性限制
- 整数溢出: 2147483647+1=-2147483648, 负数价格

### 遇到 Hash 时的策略

1. 先检查能否绕过比较（类型混淆/magic hash）
2. 对照常见密码hash表（admin/123456/password/test的md5）
3. 在线查表（cmd5.com/somd5.com）
4. 写python脚本用30个常见密码快速碰撞
5. 最后才考虑hashcat/john
