---
title: 护网初级蓝队学习笔记（三）：用 Sysmon 还原可疑进程链
published: 2025-03-15
description: 学习 Sysmon 核心事件、进程 GUID 关联、配置降噪，以及从进程到 DNS 和网络连接的时间线分析。
tags: [蓝队, Sysmon, Windows, 威胁狩猎, 进程分析]
category: 蓝队学习
draft: false
author: GGBoss
---

## Sysmon 能解决什么问题

Windows 4688 可以记录进程创建，但 Sysmon 会补充父进程、完整命令行、哈希、`ProcessGuid`、DNS 和网络连接等上下文。官方文档强调，Sysmon 只提供遥测，不会自动判断恶意；真正的价值来自事件关联。

日志路径：

```text
Applications and Services Logs
└─ Microsoft
   └─ Windows
      └─ Sysmon
         └─ Operational
```

Sysmon 时间使用 UTC，和本地安全日志、WAF 日志对齐时必须先统一时区。

## 一、初级蓝队优先掌握的事件

| Sysmon ID | 行为 | 排查用途 |
| --- | --- | --- |
| 1 | 进程创建 | 父子进程、命令行、哈希 |
| 3 | 网络连接 | 哪个进程连接了哪个地址 |
| 6 | 驱动加载 | 可疑或未签名驱动 |
| 7 | 映像加载 | DLL 加载与侧载，数据量较大 |
| 10 | 进程访问 | 进程注入、凭据访问线索 |
| 11 | 文件创建 | 下载器、落地载荷、WebShell |
| 12～14 | 注册表变更 | 启动项和配置篡改 |
| 17～18 | 命名管道 | 进程间通信 |
| 19～21 | WMI 事件 | WMI 持久化 |
| 22 | DNS 查询 | 域名解析和外联基础设施 |
| 23 / 26 | 文件删除 | 清理痕迹或勒索行为 |

[Sysmon 官方说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 特别提醒，事件 7 等高频事件必须谨慎配置，否则日志量会迅速膨胀。

## 二、进程链比单个进程更重要

`powershell.exe`、`cmd.exe`、`rundll32.exe` 本身都是合法程序。真正可疑的是上下文：

```text
WINWORD.EXE
└─ powershell.exe -EncodedCommand ...
   ├─ certutil.exe -urlcache ...
   └─ payload.exe
      └─ 外联 203.0.113.10:443
```

分析 Event ID 1 时重点看：

- `Image`：当前程序路径；
- `CommandLine`：完整参数；
- `ParentImage` 与 `ParentCommandLine`；
- `User` 与 `IntegrityLevel`；
- `Hashes`；
- `ProcessGuid` 和 `ParentProcessGuid`。

PID 会被系统复用，跨较长时间关联时应优先使用 `ProcessGuid`。

## 三、从一个告警扩展调查

假设告警命中 PowerShell 编码执行：

1. 用 Event ID 1 找到进程的 `ProcessGuid`；
2. 查相同 `ProcessGuid` 的 Event ID 3，确认网络目标；
3. 查 Event ID 22，确定此前解析的域名；
4. 查其子进程 Event ID 1；
5. 查 Event ID 11，确认是否写入文件；
6. 用哈希在 EDR、SIEM 或文件库中搜索其他主机；
7. 用 `ParentProcessGuid` 向上还原入口。

MITRE ATT&CK 的检测思路也经常把进程创建与网络连接组合。例如 [Web 服务 C2 检测策略](https://attack.mitre.org/detectionstrategies/DET0035/) 同时使用 Sysmon 1、3、22，而不是依赖单一 IOC。

## 四、安装与配置验证

授权测试机中的基础命令：

```powershell
Sysmon64.exe -accepteula -i .\sysmon-config.xml
Sysmon64.exe -c
Sysmon64.exe -s
```

更新配置：

```powershell
Sysmon64.exe -c .\sysmon-config.xml
```

配置应遵循“收集能回答问题的数据”，而不是无差别全开。下面是一个教学用片段：

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <DnsQuery onmatch="exclude">
      <QueryName condition="end with">.internal.example</QueryName>
    </DnsQuery>
    <NetworkConnect onmatch="include">
      <Image condition="end with">powershell.exe</Image>
      <Image condition="end with">rundll32.exe</Image>
      <Image condition="end with">mshta.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

这不是生产配置。生产中还要考虑版本 schema、业务程序、日志量、隐私和攻击者规避，并在测试环境验证。

## 五、配置降噪的方法

1. 先观察数据量，再决定排除项；
2. 排除必须足够具体，例如路径、签名、父进程和目的地址组合；
3. 不要仅按文件名放行，因为攻击者可以重命名；
4. 高价值服务器可以比普通终端收集更多事件；
5. 每条排除规则写明业务依据、负责人和复核日期；
6. 监控 Sysmon 停止、配置修改和内部错误事件。

微软的 [Sysmon 调优文档](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/read-tune-sysmon-events) 建议关注异常父子关系、非常规命令行、用户可写目录中的可执行文件和不应联网的进程。

## 六、我总结的狩猎查询逻辑

```text
可疑入口：
  Office / 浏览器 / PDF 阅读器 → 脚本解释器

可疑执行：
  powershell / wscript / cscript / mshta / rundll32
  + 编码、下载、隐藏窗口、绕过策略等参数

可疑落地：
  Temp / AppData / Downloads / Public
  + EXE、DLL、脚本、快捷方式

可疑外联：
  上述进程 → 首次出现域名或稀有 IP

可疑持久化：
  上述进程 → Run 键、计划任务、服务、WMI
```

每个条件单独看都可能误报，组合后可信度才会上升。

## 本篇小结

Sysmon 学习的关键是把事件还原成故事：谁启动了谁、执行了什么、写了什么、解析了什么、连接了哪里。对于初级蓝队，熟练还原一条进程链，比背完所有事件 ID 更有用。

## 参考资料

- [Microsoft Sysinternals：Sysmon 官方文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Learn：读取和调优 Sysmon 事件](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/read-tune-sysmon-events)
- [MITRE ATT&CK：Web 服务 C2 的进程与网络关联检测](https://attack.mitre.org/detectionstrategies/DET0035/)
