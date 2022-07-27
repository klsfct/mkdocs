# 雷电模拟器安装xposed框架



https://forum.xda-developers.com/t/phoenix-os-2-6-3-x86_64-xposed-framework-v89-sdk25-by-youling257.3686255/



xposed inspeckage



#### 0x01 渗透思路

##### 0x01-1 四大组件渗透

Android 开发的四大组件分别是：活动（activity），用于表现功能；服务（service），后台运行服务，不提供界面呈现；广播接受者（Broadcast Receive），勇于接收广播；内容提供者（Content Provider），支持多个应用中存储和读取数据，相当于数据库。
四大组件渗透可能会获得一些敏感信息，这里我们使用Drozer安全测试框架进行测试。
获取方式：后台回复Drozer

0x01-2 APP应用层渗透
app应用层渗透思路可以直接运用web渗透测试流程，通过抓包分析找到一些交互点，通过分析参数挖掘是否有注入漏洞等，这里的目标是getshell，也是我们目前的重点。

0x01-3 反编译
反编译即需要通过逆向工程的手段对app进行脱壳后反编译处理，需要的时间很长，难度较高。

0x02 apk包体的基本结构
对于一个apk包，我们只需要把后缀改为.zip然后通过压缩工具打开即可，或者最好直接右键——打开方式——选择解压工具。



即可看到apk包的目录结构。
其中META-INF是apk的签名文件，是apk正盗版的唯一标识。
AndroidManifest.xml是apk的配置清单文件，它标识着一个apk有多少个界面（服务）。
Classes.dex是代码文件，由java编译过来的，加壳的位置也是在这。
Resources.arsc是字符文件，例如汉化等就需要在这里进行。
res文件夹是图标、图片所在
Assets文件夹是其他文件所在位置
任何apk的基本结构都是这样，上述几个文件除Assets外其他都必不可少。

0x03 反编译
这里需要jdk环境及jadx或Android Killer
Android Killer是一款可以对APK进行反编译的工具，虽然是几年前的工具了但是放在今天依然好用。它能够对反编译后的Smali文件进行修改，并将修改后的文件进行打包。
Smali：Androidmanifest.xml中代码入口等信息，编译后生成dex可执行文件，逆向时会解析dex文件生成smali文件夹、smali文件夹中存放逆向出来的Java代码，可以使用工具进行查看。
本文所使用的反编译工具为jadx，jadx是个人比较喜欢的一款反编译利器，同时支持命令行和图形界面，能以最简便的方式完成apk的反编译操作。



# 移动安全app渗透测试之渗透流程、方案及测试要点讲解

https://blog.csdn.net/shuryuu/article/details/103084983?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_utm_term~default-0-103084983-blog-107749130.pc_relevant_default&spm=1001.2101.3001.4242.1&utm_relevant_index=1