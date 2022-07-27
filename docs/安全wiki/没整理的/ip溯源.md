## IP溯源

### 网络空间属性

#### 国内

##### 判断方法

###### 一些常用会标记IP属性的网站

www.ipip.net

优点：准确，信息量大

缺点：API需要收费，每天有次数限制

ipwhois.cnnic.net.cn

CNNIC的信息较为准确

地址状态:	

ALLOCATED PORTABLE 

动态IP，包含5G/4G/家庭宽带等

云VPS的IP也会标记成这个，需要结合 单位描述来处理

ALLOCATED NON-PORTABLE 

静态IP，比如专线宽带/IDC机房/企业出口

单位描述:

三大运营商

其他VPS云厂商

其他拥有IP分配权的大型公司

baidu直接搜IP

腾讯云/阿里云这类型的IP可直接搜索出

IP库

ip2region

https://github.com/lionsoul2014/ip2region

推荐

淘宝IP库

https://www.aliyun.com/product/dns/geoip

api

http://ip.taobao.com/ipSearch?ipAddr=117.132.195.140

###### 反查rdns中带有static的

举例：36.110.xx.xx的RDNS是xx.xx.110.36.static.bjtelecom.net

##### 分类

###### 静态IP

企业专线/企业出口

一般端口扫描后会有网络/安全设备，比如防火墙，路由器，同时也会有一些系统直接映射到外网，可以从业务系统或反查域名商了解到IP所属是哪家企业

如果是企业出口发起攻击，还有可能是出口下面的个人机器感染后对外发起扫描。

IDC机房

一般同C段IP会开放大量Web端口，且C段可能会出现不同的单位网站，此类型IP为托管服务器，除非为安全企业自身托管的服务器（如漏扫），更多可能是存在漏洞被控后发起攻击

###### 动态IP

家庭宽带

家庭宽带虽然会不定期更换，但基本都是在一个IP池子里，更换后，IP定位也基本都是在一片区域，运营商处存在每次分配IP的记录，如果能确定动态IP为真实攻击者IP，报警后证据真实有效公安可找到对应的人员。

3G/4G/5G等wap

移动IP难以在互联网信息层面进行溯源

###### IDC出口

1.正常的服务器被控制后成为代理/肉鸡

网页为正常业务网站，但是存在漏洞可拿到权限

2.为一些安全企业托管的主动扫描类型的设备

比如多地ping，在线漏扫这种在线服务所承载的设备

3.托管在机房的VPN类型设备

提供VPN/代理的在线服务所承载的设备，一般可扫描出网站业务的端口或者VPN常用端口

###### 云供应商

VPS

网络安全从业者

一般开放端口笔记少，一般为22,3389，临时开放的Web端口可能是为了从VPS上下载东西，可以尝试扫描全端口，看是否开着一些安全工具/系统的页面。

失陷肉鸡

IP开放着网站运营这正常的业务，或者为简单的CMS站点，多数存在漏洞，可以尝试该Web应用或者CMS的通用漏洞，即可拿下。

CDN

反向查询域名，短时间内绑定大量域名

验证方法：浏览器访问ip的Web端口，截包修改host字段为IP反查出域名的网站，如果能访问则代表为CDN

验证方法：访问https://tools.ipip.net/cdn.php查询IP

一般来说CDN的IP不会为攻击源IP，遇到攻击源IP是CDN的情况，最大可能性应该是：该IP是业务网站（防护的网站）购买的CDN IP，安全监控设备部署在CDN之后，将CDN的IP作为攻击源IP显示。

黑产

IP开放着网站端口，涉及到黑产业务的

IP近期历史绑定的域名存在大量博彩/色情等黑产网站

网站托管

基于lamp的网站托管方式，一般不会成为攻击源

网站托管跟恶意活动挂钩的更多的是成为C&C地址

国外

判断方法

常用的IP标记网站

myip.ms

IP归属的运营商或者VPS云厂商信息较多

IP真人率，此网站也会记录该IP的UA部分信息

virustotal.com

反查域名

查是否有关联到的样本

查IP归属的运营商或者ASN

community.riskiq.com

强力推荐

反查域名

HTTPS证书

历史网站

IP归属的运营商注册的Whois信息

其他情报网站的导航

反查域名

常用的反查域名网站

https://community.riskiq.com/

https://www.virustotal.com/gui/home/search

https://x.threatbook.cn/

https://quake.360.cn/





#### 国外

(https://community.riskiq.com/, https://www.virustotal.com/gui/home/search)

国内
(https://x.threatbook.cn/, https://quake.360.cn/)

实时绑定的域名

域名的Whois信息

https://www.whois.net/default.aspx

https://who.is/

https://community.riskiq.com/

http://whois.chinaz.com/

https://whois.aliyun.com/

http://whois.xinnet.com/

国外
(https://www.whois.net/default.aspx, https://who.is/, https://community.riskiq.com/)

国内
(http://whois.chinaz.com/, https://whois.aliyun.com/, http://whois.xinnet.com/)

域名备案信息

https://icp.chinaz.com/

https://www.chaicp.com/

https://gaj.sh.gov.cn/wa/newlogin/recordSearch.jsp

子域名

子域名的实时解析IP和历史解析IP都可以作为新的IP进行溯源关联

域名的历史解析IP

如果解析时间相近的话可以作为新的IP进行溯源关联

历史域名

判断历史域名绑定IP的时间和目前是否偏差过久

比如IP是VPS，历史域名和现在域名的绑定时间相差超过1年，基本关联性就不打

如果IP为静态IP，一般情况历史域名都是属于同一单位的





### 地理定位

#### 境内

高德地图修改XFF头的方式确定IP定位

IP定位的一些常用搜索网站

www.opengps.cn

www.ipplus360.com

www.chaipip.com

www.ipip.net

#### 境外

IP定位常用的搜索网站

iplocation.com

子主题 2

IP库

https://dev.maxmind.com/geoip/geoip2/geolite2/

google高精准定位

google精准定位API







### IP开放端口

#### 主动探测

##### 同C段IP

TOP1000端口扫描

Nmap -T4

同C段开放大量80及443的端口，且都运行了正常的业务

结合网络空间属性定位，判断是否为IDC/VPS或者企业出口

专线（静态IP）一般购买时至少购买4个IP，所以目标IP可能跟附近的IP也属于同一个组织

同C段未开放任何端口，或者只有家庭路由器的端口

推断为动态IP

同C段扫描Title

比如同段所有的网站Title都是政府网站，该段可能为政务云或者某地市政府信息化机房/出口

##### 攻击源IP

全端口扫描

ilab自研发的扫描器

API接口

##### 端口及服务扫描结果

###### 默认VPN类型端口

5555:SoftEther VPN

TCP/UDP

1723:PPTP VPN

TCP

500:L2TP VPN

UDP

4500:L2TP VPN

UDP

1701:L2TP VPN

UDP

1194:Openvpn

TCP/UDP

5000:Vtun 

TCP/UDP

12975:	LogMeIn Hamachi

TCP/UDP

1080:其他SOCKS5类代理常用端口

TCP

参考

https://wsgzao.github.io/post/service-names-port-numbers/

等等...

###### 默认管理类端口

X3389

RDP

X22

SSH

8088

宝塔管理界面默认端口

8888

宝塔管理宝塔管理界面默认端口

5500

VNC远程桌面协议-用于传入监听查看器，热线控制连接

5800

VNC远程桌面协议-通过HTTP使用

5900+

VNC远程桌面协议(由ARD使用)

端口是从5900开始增加的

等等...

###### 应用服务端口

Web应用服务的Title

正常的业务网站

可能此IP是肉鸡，大概率网站存在漏洞，可拿下做后查看日志做上一跳溯源

参见: 有概率是业务网站，需要绑定域名才能访问，可以通过反查域名的方式，IP访问后修改host头为反查的域名，可能会跳转到有效URL路径 (同理)

默认的一些Web应用界面

有概率是业务网站，需要绑定域名才能访问，可以通过反查域名的方式，IP访问后修改host头为反查的域名，可能会跳转到有效URL路径

参见: 可能此IP是肉鸡，大概率网站存在漏洞，可拿下做后查看日志做上一跳溯源 (同理)

可以尝试使用Web路径扫描器扫描路径

有概率是攻击者的VPS，搭建Web服务为了C&C上线或者下载黑客工具，这种情况也可以爆破URL路径

其他硬件设备

安全设备/网络设备

硬件防火墙

为企业出口，个人或者家庭不可能去买企业安全设备，大概率是企业出口下面的主机可能失陷后对外攻击

路由器

看路由器品牌和型号，判断你是家用还是商用产品，判断后的逻辑见上语句

物联网设备

多为僵尸网络的肉鸡，通过弱密码/对应物联网设备都可拿下

一些常用黑客工具开放服务的默认title

比如nps，hfs等等

###### C&C监听端口或黑客工具端口

50050

Cobalt Strike

8080

nps

一些自定义木马也喜欢用这种类型的端口

8834

nessusWeb界面管理端口

4444

hfs

等等....

###### 肉鸡类型

存在一些常用漏洞

wordpress漏洞

phpmyadmin漏洞

tomcat漏洞

weblogic漏洞

等等...

存在一些通用管理类弱密码

对IP反查时建议也加上自动化漏扫，扫出来有漏洞的大部分是跳板机/肉鸡
(存在一些常用漏洞, 存在一些通用管理类弱密码)

###### SSL证书

从端口服务绑定的SSL证书中可以获取域名信息或者该网站所属业务的信息（比如VPN设备的SSL证书会有VPN厂家）

从SSL证书可以反查出域名信息

比如黑客以前可以会拿VPS绑定一些个人注册的域名，后来弃用了，但是可以通过保存历史SSL证书的网站进行回溯

常用搜索网站

https://community.riskiq.com/

VPN类型端口一般为跳板机或者企业出口
(默认VPN类型端口)

开放远程管理类的IP大概率为攻击者可控（自用）的跳板机
(默认管理类端口)

互联网第三方暴露面库

优点

无需等待扫描结束，利用API可直接获取，针对查大量IP时效率更高

可获取历史开放的端口和服务

缺点

没有实时扫描的准确度高，历史开放的端口/服务可能目前已经关闭

常用网址

https://censys.io/

https://community.riskiq.com/

https://www.shodan.io/

https://fofa.so/

http://www.zoomeye.org/

https://www.virustotal.com/gui/home/search

https://x.threatbook.cn/

国内
(https://fofa.so/, http://www.zoomeye.org/, https://www.virustotal.com/gui/home/search, https://x.threatbook.cn/)

国外
(https://censys.io/, https://community.riskiq.com/, https://www.shodan.io/)

#### 威胁情报

##### 常用的威胁情报网站

##### 主要通过威胁情报来对IP进行分类

无查询到任何情报

标签为病毒木马蠕虫

标签为APT组织

标签为攻击漏洞利用



##### 通过威胁情报关联更多线索

匹配到沙箱报告

分析具体的木马程序，看是偏向于自动化蠕虫类型的还是黑客木马的

匹配到安全人员的分析报告

可以通过报告了解其他人关于此IP的分析结果

匹配到被互联网蜜罐标记为曾经攻击过

基本可以排除此IP的定向攻击可能性

等等..看具体情况而定

#### 搜索引擎

利用搜索引擎直接搜索IP

IP可能会在论坛留言/网站日志中遗留痕迹，可能会被搜索引擎收录

建议使用google

搜索引擎的方式很有效，一些长期活动的IP，可以通过搜索引擎关联出沙箱报告、论坛活动痕迹、Web日志、pcap包分析公开结果等等..