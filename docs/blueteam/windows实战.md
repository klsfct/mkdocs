

## 第1篇：FTP暴力破解

### 0x00 前言

 FTP是一个文件传输协议，用户通过FTP可从客户机程序向远程主机上传或下载文件，常用于网站代码维护、日常源码备份等。如果攻击者通过FTP匿名访问或者弱口令获取FTP权限，可直接上传webshell，进一步渗透提权，直至控制整个网站服务器。

### 0x01 应急场景

 从昨天开始，网站响应速度变得缓慢，网站服务器登录上去非常卡，重启服务器就能保证一段时间的正常访问，网站响应状态时而飞快时而缓慢，多数时间是缓慢的。针对网站服务器异常，系统日志和网站日志，是我们排查处理的重点。查看Window安全日志，发现大量的登录失败记录：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-1.png)

### 0x02 日志分析

**安全日志分析：**

安全日志记录着事件审计信息，包括用户验证（登录、远程访问等）和特定用户在认证后对系统做了什么。

打开安全日志，在右边点击筛选当前日志， 在事件ID填入4625，查询到事件ID4625，事件数177007，从这个数据可以看出，服务器正则遭受暴力破解：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-2.png)

进一步使用Log Parser对日志提取数据分析，发现攻击者使用了大量的用户名进行爆破，例如用户名：fxxx，共计进行了17826次口令尝试，攻击者基于“fxxx”这样一个域名信息，构造了一系列的用户名字典进行有针对性进行爆破，如下图：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-3.png)

这里我们留意到登录类型为8，来了解一下登录类型8是什么意思呢？

**登录类型8：网络明文（NetworkCleartext）**

这种登录表明这是一个像类型3一样的网络登录，但是这种登录的密码在网络上是通过明文传输的，WindowsServer服务是不允许通过明文验证连接到共享文件夹或打印机的，据我所知只有当从一个使用Advapi的ASP脚本登录或者一个用户使用基本验证方式登录IIS才会是这种登录类型。“登录过程”栏都将列出Advapi。

我们推测可能是FTP服务，通过查看端口服务及管理员访谈，确认服务器确实对公网开放了FTP服务。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-4.png)

另外，日志并未记录暴力破解的IP地址，我们可以使用Wireshark对捕获到的流量进行分析，获取到正在进行爆破的IP：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-5.png)

通过对近段时间的管理员登录日志进行分析，如下：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-6.png)

管理员登录正常，并未发现异常登录时间和异常登录ip，这里的登录类型10，代表远程管理桌面登录。

另外，通过查看FTP站点，发现只有一个测试文件，与站点目录并不在同一个目录下面，进一步验证了FTP暴力破解并未成功。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-5-7.png)

应急处理措施：1、关闭外网FTP端口映射 2、删除本地服务器FTP测试

### 0x04 处理措施

 FTP暴力破解依然十分普遍，如何保护服务器不受暴力破解攻击，总结了几种措施：

```
1、禁止使用FTP传输文件，若必须开放应限定管理IP地址并加强口令安全审计（口令长度不低于8位，由数字、大小写字母、特殊字符等至少两种以上组合构成）。
2、更改服务器FTP默认端口。
3、部署入侵检测设备，增强安全防护。
```

## 第2篇：蠕虫病毒

### 0x00 前言

 蠕虫病毒是一种十分古老的计算机病毒，它是一种自包含的程序（或是一套程序），通常通过网络途径传播，每入侵到一台新的计算机，它就在这台计算机上复制自己，并自动执行它自身的程序。

常见的蠕虫病毒：熊猫烧香病毒 、冲击波/震荡波病毒、conficker病毒等。

### 0x01 应急场景

 某天早上，管理员在出口防火墙发现内网服务器不断向境外IP发起主动连接，内网环境，无法连通外网，无图脑补。

### 0x02 事件分析

在出口防火墙看到的服务器内网IP，首先将中病毒的主机从内网断开，然后登录该服务器，打开D盾_web查杀查看端口连接情况，可以发现本地向外网IP发起大量的主动连接：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-6-1.png)

通过端口异常，跟踪进程ID，可以找到该异常由svchost.exe windows服务主进程引起，svchost.exe向大量远程IP的445端口发送请求：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-6-2.png)

这里我们推测可以系统进程被病毒感染，使用卡巴斯基病毒查杀工具，对全盘文件进行查杀，发现c:\windows\system32\qntofmhz.dll异常：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-6-3.png)

使用多引擎在线病毒扫描（http://www.virscan.org/） 对该文件进行扫描:

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-6-4.png)

确认服务器感染conficker蠕虫病毒，下载conficker蠕虫专杀工具对服务器进行清查，成功清楚病毒。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-6-5.png)

大致的处理流程如下:

```
1、发现异常：出口防火墙、本地端口连接情况，主动向外网发起大量连接
2、病毒查杀：卡巴斯基全盘扫描，发现异常文件
3、确认病毒：使用多引擎在线病毒对该文件扫描，确认服务器感染conficker蠕虫病毒。
4、病毒处理：使用conficker蠕虫专杀工具对服务器进行清查，成功清除病毒。
```

### 0x04 **预防处理措施**

 在政府、医院内网，依然存在着一些很古老的感染性病毒，如何保护电脑不受病毒感染，总结了几种预防措施：

```
1、安装杀毒软件，定期全盘扫描
2、不使用来历不明的软件，不随意接入未经查杀的U盘
3、定期对windows系统漏洞进行修复，不给病毒可乘之机
4、做好重要文件的备份，备份，备份。
```

## 第3篇：勒索病毒

### 0x00 前言

 勒索病毒，是一种新型电脑病毒，主要以邮件、程序木马、网页挂马的形式进行传播。该病毒性质恶劣、危害极大，一旦感染将给用户带来无法估量的损失。这种病毒利用各种加密算法对文件进行加密，被感染者一般无法解密，必须拿到解密的私钥才有可能破解。自WannaCry勒索病毒在全球爆发之后，各种变种及新型勒索病毒层出不穷。

### 0x01 应急场景

 某天早上，网站管理员打开OA系统，首页访问异常，显示乱码：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-7-1.png)

### 0x02 事件分析

 登录网站服务器进行排查，在站点目录下发现所有的脚本文件及附件都被加密为.sage结尾的文件，每个文件夹下都有一个!HELP_SOS.hta文件，打包了部分样本：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-7-2.png)

打开!HELP_SOS.hta文件，显示如下：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-7-3.png)

到这里，基本可以确认是服务器中了勒索病毒，上传样本到360勒索病毒网站（http://lesuobingdu.360.cn）进行分析：确认web服务器中了sage勒索病毒，目前暂时无法解密。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-7-4.png)

绝大多数勒索病毒，是无法解密的，一旦被加密，即使支付也不一定能够获得解密密钥。在平时运维中应积极做好备份工作，数据库与源码分离（类似OA系统附件资源也很重要，也要备份）。

遇到了，别急，试一试勒索病毒解密工具：

```
“拒绝勒索软件”网站
https://www.nomoreransom.org/zh/index.html
360安全卫士勒索病毒专题
http://lesuobingdu.360.cn
```

### 0x04 防范措施

 一旦中了勒索病毒，文件会被锁死，没有办法正常访问了，这时候，会给你带来极大的困恼。为了防范这样的事情出现，我们电脑上要先做好一些措施：

```
1、安装杀毒软件，保持监控开启，定期全盘扫描
2、及时更新 Windows安全补丁，开启防火墙临时关闭端口，如445、135、137、138、139、3389等端口
3、及时更新web漏洞补丁，升级web组件
4、备份。重要的资料一定要备份，谨防资料丢失
5、强化网络安全意识，陌生链接不点击，陌生文件不要下载，陌生邮件不要打开
```



## 第4篇：ARP病毒

### 0x00 前言

　　ARP病毒并不是某一种病毒的名称，而是对利用arp协议的漏洞进行传播的一类病毒的总称，目前在局域网中较为常见。发作的时候会向全网发送伪造的ARP数据包，严重干扰全网的正常运行，其危害甚至比一些蠕虫病毒还要严重得多。

### 0x01 应急场景

　　某天早上，小伙伴给我发了一个微信，说192.168.64.76 CPU现在负载很高，在日志分析平台查看了一下这台服务器的相关日志，流量在某个时间点暴涨，发现大量137端口的UDP攻击。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-1.png)

### 0x02 分析过程

　　登录服务器，首先查看137端口对应的进程，进程ID为4对应的进程是SYSTEM，于是使用杀毒软件进行全盘查杀。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-2.png)

卡巴斯基绿色版：http://devbuilds.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe

卡巴斯基、360杀毒、McAfee查杀无果，手工将启动项、计划任务、服务项都翻了一遍，并未发现异常。 本地下载了IpTool抓包工具，筛选条件： 协议 UDP 端口 137

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-3.png)

可以明显的看出192.168.64.76发送的数据包是异常的，192.168.64.76的数据包目的地址，一直在变，目的MAC是不变的，而这个MAC地址就是网关的MAC。

端口137的udp包是netbios的广播包，猜测：可能是ARP病毒，由本机对外的ARP攻击。

采用措施：通过借助一些安全软件来实现局域网ARP检测及防御功能。

服务器安全狗Windows版下载：http://free.safedog.cn/server_safedog.html

网络防火墙--攻击防护--ARP防火墙：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-4.png)

虽然有拦截了部分ARP请求，但流量出口还是有一些137 UDF的数据包。

看来还是得下狠招，关闭137端口：禁用TCP/IP上的NetBIOS。

1）、禁用Server服务

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-5.png)

2）、禁用 TCP/IP 上的 NetBIOS

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-9-6.png)

设置完，不用重启即可生效，137端口关闭，观察了一会，对外发起的请求已消失，CPU和网络带宽恢复正常。

### 0x04 防护措施

　　局域网安全防护依然是一项很艰巨的任务，网络的安全策略，个人/服务器的防毒机制，可以在一定程度上防止病毒入侵。

　　另外不管是个人PC还是服务器，总还是需要做一些基本的安全防护：1、关闭135/137/138/139/445等端口 2、更新系统补丁。

## 第5篇：挖矿病毒（一）

### 0x00 前言

 随着虚拟货币的疯狂炒作，挖矿病毒已经成为不法分子利用最为频繁的攻击方式之一。病毒传播者可以利用个人电脑或服务器进行挖矿，具体现象为电脑CPU占用率高，C盘可使用空间骤降，电脑温度升高，风扇噪声增大等问题。

### 0x01 应急场景

 某天上午重启服务器的时候，发现程序启动很慢，打开任务管理器，发现cpu被占用接近100%，服务器资源占用严重。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-8-1.png)

### 0x02 事件分析

 登录网站服务器进行排查，发现多个异常进程：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-8-2.png)

分析进程参数：

wmic process get caption,commandline /value >> tmp.txt

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-8-3.png)

TIPS:

```
在windows下查看某个运行程序（或进程）的命令行参数
使用下面的命令：
wmic process get caption,commandline /value
如果想查询某一个进程的命令行参数，使用下列方式：
wmic process where caption=”svchost.exe” get caption,commandline /value
这样就可以得到进程的可执行文件位置等信息。
```

访问该链接：

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-8-4.png)

Temp目录下发现Carbon、run.bat挖矿程序:

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-8-5.png)

具体技术分析细节详见：

> 360CERT：利用WebLogic漏洞挖矿事件分析
>
> https://www.anquanke.com/post/id/92223

清除挖矿病毒：关闭异常进程、删除c盘temp目录下挖矿程序 。

**临时防护方案**

1. 根据实际环境路径，删除WebLogic程序下列war包及目录

   rm -f /home/WebLogic/Oracle/Middleware/wlserver_10.3/server/lib/wls-wsat.war

   rm -f /home/WebLogic/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/.internal/wls-wsat.war

   rm -rf /home/WebLogic/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/wls-wsat

2. 重启WebLogic或系统后，确认以下链接访问是否为404

   http://x.x.x.x:7001/wls-wsat

### 0x04 防范措施

 新的挖矿攻击展现出了类似蠕虫的行为，并结合了高级攻击技术，以增加对目标服务器感染的成功率。通过利用永恒之蓝（EternalBlue）、web攻击多种漏洞，如Tomcat弱口令攻击、Weblogic WLS组件漏洞、Jboss反序列化漏洞，Struts2远程命令执行等，导致大量服务器被感染挖矿程序的现象 。总结了几种预防措施：

```
1、安装安全软件并升级病毒库，定期全盘扫描，保持实时防护
2、及时更新 Windows安全补丁，开启防火墙临时关闭端口
3、及时更新web漏洞补丁，升级web组件
```

## 第6篇：挖矿病毒（二）

### 0x00 前言

　　作为一个运维工程师，而非一个专业的病毒分析工程师，遇到了比较复杂的病毒怎么办？别怕，虽然对二进制不熟，但是依靠系统运维的经验，我们可以用自己的方式来解决它。

### 0x01 感染现象

1、向大量远程IP的445端口发送请求

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-1.png)

2、使用各种杀毒软件查杀无果，虽然能识别出在C:\Windows\NerworkDistribution中发现异常文件，但即使删除NerworkDistribution后，每次重启又会再次生成。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-2.jpg)

连杀软清除不了的病毒，只能手工来吧，个人比较偏好火绒，界面比较简洁，功能也挺好用的，自带的火绒剑是安全分析利器。于是安装了火绒，有了如下分析排查过程。

### 0x02 事件分析

#### A、网络链接

通过现象，找到对外发送请求的进程ID：4960

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-3.png)

#### B、进程分析

进一步通过进程ID找到相关联的进程，父进程为1464

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-4.png)

找到进程ID为1464的服务项，逐一排查，我们发现服务项RemoteUPnPService存在异常。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-5.png)

#### C、删除服务

选择可疑服务项，右键属性，停止服务，启动类型：禁止。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-6.png)

停止并禁用服务，再清除NerworkDistribution目录后，重启计算机。异常请求和目录的现象消失。

又排查了几台，现象一致，就是服务项的名称有点变化。

![img](https://bypass007.github.io/Emergency-Response-Notes/Windows/image/win-10-7.png)

#### D、病毒清除

挖矿病毒清除过程如下：

1、 停止并禁用可疑的服务项，服务项的名称会变，但描述是不变的，根据描述可快速找到可疑服务项。

 可疑服务项描述：Enables a common interface and object model for the Remote UPnP Service to access

 删除服务项：Sc delete RemoteUPnPService

2、 删除C:\Windows\NerworkDistribution目录

3、 重启计算机

4、 使用杀毒软件全盘查杀

5、 到微软官方网站下载对应操作系统补丁，下载链接：

　　https://docs.microsoft.com/zh-cn/security-updates/securitybulletins/2017/ms17-010

### 0x03 后记

在查询了大量资料后，找到了一篇在2018年2月有关该病毒的报告：

NrsMiner：一个构造精密的挖矿僵尸网络

https://www.freebuf.com/articles/system/162874.html

根据文章提示，这个病毒的构造非常的复杂，主控模块作为服务“Hyper-VAccess Protection Agent Service”的ServiceDll存在。但与目前处理的情况有所不同，该病毒疑似是升级了。