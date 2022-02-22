### 条件竞争漏洞

### xxs漏洞

反射、dom、存储

盗取用户Cookie、未授权操作、修改DOM、刷浮窗广告、发动XSS蠕虫攻击、
劫持用户行为，进一步渗透内网。

防护

1)将HTML元素内容、属性以及URL请求参数、CSS 值进行编码
2)当编码影响业务时，使用白名单规则进行检测和过滤
3)使用W3C提出的CSP (Content Security Policy, 内容安全策略)，定义域名白名单
4)设置cookie的httponly属性



### csrf

1)最容易实现的是Get请求，一般进入黑客网站后，可以通过设置img的src属
性来自动发起请求
2)在黑客的网站中，构造隐藏表单来自动发起Post请求
3)通过引诱链接诱惑用户点击触发请求，利用a标签的href


防护

1)针对实际情况，设置关键Cookie 的SameSite属性为Strict 或Lax
2)服务端验证请求来源站点(Referer、Origin)
3)使用CSRFToken,服务端随机生成返回给浏览器的Token,每-次请求都会携带不同的CSRF Token
4)加入二次验证

45、token和referer做横向对比，谁安全等级高
token安全等级更高，因为并不是任何服务器都可以取得referer, 如果从HTTPS
跳到HTTP,也不会发送referer。并且FLASH一些版本中可以自定义referer。但
是token的话，要保证其足够随机且不可泄露。

46、对referer的验证，从什么角度去做?如果做，怎么杜绝问题
对header中的referer的验证，- 个是空referer,一个是referer过滤或者检测
不完善。为了杜绝这种问题，在验证的白名单中，正则规则应当写完善。99
47、针对token攻击，你会对token的哪方面进行测试
针对token的攻击，一是对它本 身的攻击，重放测试一次性、 分析加密规则、校
验方式是否正确等，二是结合信息泄露漏洞对它的获取，结合着发起组合攻击。
信息泄露有可能是缓存、日志、get,也有可能是利用跨站。很多跳转登录的都
依赖token,有一个跳转漏洞加反射型跨站就可以组合成登录劫持了。
另外也可以结合着其它业务来描述token的安全性及设计不好怎么被绕过比如
抢红包业务之类的。

### 任意文件下载

利用条件:存在读文件的函数;读取文件的路径用户可控且未校验或校验不严;
输出了文件内容。
任意文件下载和任意文件读取有着相似的地方:就是都需要路径，例如
index.php?f-file:///etc/ passwd, index.php?f= ./index.php

32、任意文件下载漏洞的修复方案
1)过滤用户数据，如"/"， “*."等特殊字符
2)更新中间件
3)要下载的文件地址保存至数据库中
4)文件路径保存至数据库，让用户提交文件对应ID或session下载文件
5)用户下载文件之前需要进行权限判断
6)文件放在web无法直接访问的目录下
7)不允许提供目录遍历服务
8)公开文件可放置在weD应用程序下载目录中通过链接进行下载



### 短信重置密码

绕过方式    



### SQL注入

按数据的传递方式可以分为: get注入、post注入、cookie 注入
根据注入点类型分类:数字型、字符型
根据执行效果分类:有回显的注入、盲注、报错注入、堆叠注入、宽字节注入
操作，交易或业务步骤绕过。

字符被转义

宽字节，hex编码

15、代码执行，文件读取，命令执行的函数都有哪些
1)代码执行:
eval,preg_ replacc+/e,assert,call user. func,call user _func arry,create function
2)文件读取:
file get .contents0,highlight file0,fopen0.readfle0.fread0.fgetss),
fgets().parse_ in_ file(),show_ source),file()
3)命令执行:
system(, exec(), shell exec0, passthru() .pcntl. exec(. popen),proc open)

防护

参数化查询

18、宽字节注入产生原理以及根本原因
1)产生原理:在数据库使用了宽字符集而WEB中没考虑这个问题的情况下，由
于0XBF27是两个字符，在PHP中adcslash和magic _quotes. gpc开启时，会对
0x27单引号进行转义，因此0xbf27会变成0xbf5c27。
而数据进入数据库中时，由于0XBF5C是一-个另外的字符，因此\转义符号会被
前面的bf带着"吃掉"，单引号由此逃逸出来可以用来闭合语句。
2)根本原因:
character. set _lient(客 户端的字符集)和character. set connection(连接层的字符
集)不同,或转换函数如，iconv、 mb. convert. encoding使用不当。

解决办法:统一数据库、Web应用、操作系统所使用的字符集，避免解析产
生差异，最好都设置为U1F-8。或对数据进行止确的转义，如
mysql real escape string +mysql set charset的使用。

19、mysql 的网站注入5.0以上和5.0以下有什么区别
5.0以下没有information. schema这个系统表，无法列表名等.只能暴力跑表名:
5.0以下是多用户单操作，5.0以_ 上是多用户多操作。

30、Sqlmap 常用参数
-u (指定ur)
「(读取需要注入的post请求的文本)
-m (批量跑get注入)
-P
(指定注入参数)
-current-do:
(获取当前数据库)

- -table
  (枚举数据库表)
  “-amper (使用过
  waf脚本)

36、发现demo.Jsp?uid=110注入点，你有哪几种思路获取webshell,哪种是
优选
有写入权限的，构造联合查询语句使用using INTO OUTFILE,可以将查洵的输出
重定向到系统的文件中，这样去写入WeEShell使用sqlmap - os-shell原理和上
面一种相同，来直接获得一个Shell, 这样效率更高。
通过构造联合查询语句得到网站管理员的账户和密码，然后扫后台登录后台，再
在后台通过改包上传等方法上传Shell。
7)不允许提供目录遍历服务
8)公开文件可放置在weD应用程序下载目录中通过链接进行下载

41、SQL里面只有update怎么利用
先理解这句SQL: UPDATE user sET
password='MD5($password)，
nomepage= $homepage' WHERE id='id"
如果此SQL被修改成以下形式，就实现了注入。
1)修改homepage值为htpper. uereve=*3
之后SQL语句变为: UPDATE user SET paswordra'mypass
homepage=' ht:xx net', userlevel='3' WHERE id='$id"
userlevel为用户级别
2)修改password值为mypass)' WHERE username= admin'#
之后SQL语句变为: UPDATE user SET password= "MD5(mypass)' WHERE
username= 'admin'#), homepage='$romepage' WHERE id='$id'
3)修改id值为OR username= 'admin
之后SQL语句变为: UPDATE user SET password="MD5($password)';
homepage= $homepage' WHERE id=" OR username=' admin'

### SSRF

因为SSRF漏洞是让服务器发送请求的安全漏洞，所以就可以通过抓包分析发送
的请求是否是由服务器所发送的，从而来判断是否存在SSRF漏洞;法已当不行
在页面源码中查找访问的资源地址，如果该资源地址类型为茶业如息交
www.baidu. compxxphp?image= (地址) 的就可能存在SSRF漏洞。

成因:模拟服务器对其他服务器资源进行请求，没有做合法性验证。
利用:构造恶意内网P做探测，或者使用其余所支持的协议对其余服务进人
击。防御:禁止跳转，限制协议，内外网限制，URL 限制。
绕过:使用不同协议，针对IP IP格式的绕过， 针对URL, 恶意URL增天，
宇符，@之类的。301跳转-drs rbindaingo

### 文件上传

23、文件上传漏洞原理
由于程序员在对用户文件上传郁分的控制不足或者处理缺陷而导致用户可以越
过其本身权限向服务器上传可执行的动态脚本文件。
24、导致文件包含的函数
PHP: include(). include. once), require(), re-quire. once(), topen), readfile()
JSP/Servlet: ava io.Filc(), java.io.Fil- eReader()
ASP: include file, include virtual

28、文件上传漏洞绕过方法
前端Js绕过、黑白名单绕过、文件类型绕过(mime、 文件头、文件内容)、路
径截断绕过(00 截断)、中间件解析漏洞、条件竞争、次渲染 、编辑器漏洞
29、文件上传防御方法

上传目录的用户执行权限全部取消、判断文件类型、使用随机数改写文，
者和父
件路径、网站服务器和文件服务器分离、白名单检查、限制文件大小

### 金融行业常见逻辑漏洞

主要是数据的篡改(涉及
及金融数据，或部分业务的判断数据)，由竞争条件或者设
计不当引起的薄羊毛，交易门单信思泄露水平越仪对别人的账户查看或惠意操作，交易或业务步骤绕过。

37、说出至少三种业务逻辑漏洞，以及修复方式
密码找回漏洞中存在:
1)密码允许暴力破解
2)存在通用型找回凭证
3)可以跳过验证步骤
4)找回凭证可以拦包获取
等方式来通过厂商提供的密码找回功能来得到密码。

身份认证漏洞中最常见的是:
5)会话固定攻击
6)Cookie 仿冒
只要得到Session 或Cookie 即可伪造用户身份。

验证码漏洞中存在:
7)验证码允许暴力破解
8)验证码可以通过Javascipt 或者改包的方法来进行绕过

### 登录框的

xss，弱口令，sql注入，cms漏洞，找回密码逻辑漏洞，功能性的逻辑漏洞等等。

找回密码处

1.爆破验证码： 如果当验证只有4-5位存数字 爆破验证码的成功率很高 ：比如 100个线程 爆破4位的也就1分多钟就搞定：    如何修复:验证码验证字数限制加时间限制  

2.凭证在页面上 ：比如你最后设置密码的时候， url/userid=1234$type=1   这个你修改ID 就直接可以修改他人密码；  如何修复:请勿吧重要数据返回客户端 or 数据加密不可逆  

3.返回凭证: 有时候 他会把凭证 比如验证码问题答案 之类的 直接返回在html 代码里 or 数据包中  你就可以直接修改密码了  如何修复:请勿吧重要数据返回客户端  

4.未严格验证：比如你在找回密码的时候 他会把验证码发送邮箱 ，但是，在发送数据时候，你将包拦截下来 修改邮箱 就可以吧验证码发送到自己的邮箱 成功绕过邮箱  如何修复:严格验证 在发送邮箱时验证接收邮箱  

5.本地验证：有时候他会返回的状态码 还有返回参数值 如果你修改状态码为200 或者 参数值等于1 就可以绕过验证  如何修复:建议服务端验证  

6.token 可逆 ：最后在url上的参数 用户ID 加 token 结果你发现 token 可以解密 or 有规律 就可以修改ID 算出token 成功绕过  如何修复:token 不可逆 随机  

7.重新绑定 邮箱 or 手机 ： 有时候在注册完用户后 他要你绑定手机 or 邮箱  结果你还发现 uid 可控 怎么样绕过 我就不说了吧 23333..  如何修复:绑定时验证用户是否以及绑定 否则会覆盖 数据 23333...  

8.权限平行 ：有时候他最后 验证cookie  而cookie值&uid=xxxxx ; 你修改后面的UID 一样也可以 有时候 session 也可以覆盖   如何修复:cookie session 唯一  2333..  

9.注册覆盖 :有时候 明明用户已经注册 但是他是本地进行验证 有时候加个包什么时候就绕过去了 然后添加用户成功随之覆盖  如何修复:服务端用户是否已经注册 如果存在 返回false ;  

10：注册处 存在sql等其他漏洞  如何修复：这个涉及太广看官们自己想 2333... 

###  XXE

原理: XXE (XML 外部实体注入，XML External Entty)，在应用程序解析XML
输入时，当允许引用外部实体时，可构造恶意内容，导致读取任意文件、探测内
网端口、攻击内网网站、发起DoS拒绝服务攻击、执行系统命令等。
Java中的XXE支持sun.net. ww.protcco里的所有协议: http. https, fle, ftp.
mailto, jar, netdoc, 一 般利用file协议读取文件，利用http协议探测内网。
防御:配置XML处理器使用禁用DTD、禁止外部实体解析、通过黑名单过滤用
户提交的XML数据。

### 一句话

ASP: <%eval request("cmd")%>
ASP.NET: (aspx)
<%@ Page Language= "Jscript"%>
<%eval(Request.ltem["cmd"]"unsafe");%>
PHP: <?php @eval($_ REQUEST['cmd]):?>

简述PHP代码注入和命令注入的成因和危害

PHP中eval、aser. call _user. func等函数会将字符串当作PHP代码执行，日江
有对参数进行过滤。应用在调用sytem等函数时会将字符串拼接到命令行中
且没有过滤用户输人。
PHP注入会使攻击者执行任意代码getshel从而控制网站或服务器。系统注入。
使攻击者继承web服务器程序权限执行系统命令、读写文件、反弹shell,
!从而控制整个网站甚至服务器。