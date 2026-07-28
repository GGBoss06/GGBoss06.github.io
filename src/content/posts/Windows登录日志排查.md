---
title: 护网初级蓝队学习笔记（二）：Windows 登录日志排查
published: 2025-02-23
description: 梳理 Windows 安全日志中的登录成功、登录失败、特权登录与进程创建事件，并整理基础排查方法。
tags: [蓝队, Windows, 日志分析, 登录审计, PowerShell]
category: 蓝队学习
draft: false
author: GGBoss
---

## 为什么先学登录日志

护网期间常见的弱口令、密码喷洒、RDP 入侵和横向移动，最终都会在身份认证链路上留下痕迹。Windows 安全日志字段很多，但初级分析不需要死记全部事件，先掌握以下几组：

| 事件 ID | 含义 | 蓝队关注点 |
| --- | --- | --- |
| 4624 | 登录成功 | 登录类型、来源 IP、目标账号、认证包 |
| 4625 | 登录失败 | 失败原因、来源、失败频率、账号分布 |
| 4634 / 4647 | 会话结束/用户注销 | 与 4624 关联会话持续时间 |
| 4648 | 使用显式凭据 | `runas`、远程管理及横向行为 |
| 4672 | 特殊权限分配 | 管理员或高权限会话 |
| 4688 | 新进程创建 | 进程、父进程、命令行和账号 |
| 4720 | 创建用户 | 突然出现的新账号 |
| 4740 | 账号锁定 | 爆破、旧密码服务或异常认证 |

微软的 [高级审核策略文档](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration) 说明，只有正确开启审核子类别，相关事件才会进入安全日志。因此“没有日志”不等于“没有行为”。

## 一、理解 Logon Type

同一个 4624，在不同登录类型下意义不同：

- 2：本地交互登录；
- 3：网络登录，常见于 SMB、共享目录和远程访问；
- 4：批处理任务；
- 5：服务启动；
- 7：工作站解锁；
- 8：网络明文凭据；
- 9：使用新凭据；
- 10：远程交互，常见于 RDP；
- 11：缓存交互登录。

排查时不能看到 4624 就认定异常。例如服务器上大量类型 3 可能是正常文件共享；但普通办公账号在凌晨从新地址以类型 10 登录核心服务器，就值得升级。

## 二、4625 登录失败怎么看

微软的 [4625 事件说明](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) 给出了常见状态码：

- `0xC0000064`：用户名不存在；
- `0xC000006A`：用户名正确但密码错误；
- `0xC000006D`：用户名或认证信息错误；
- `0xC000006F`：不在允许登录时间；
- `0xC0000070`：不允许从该工作站登录；
- `0xC0000072`：账号已禁用；
- `0xC000015B`：未授予所需登录类型。

两类典型模式：

```text
单个源 IP → 大量用户名 → 少量密码
可能是密码喷洒或用户枚举

单个源 IP → 单个用户名 → 大量密码
可能是口令爆破，也可能是服务保存了旧密码
```

必须结合成功登录继续查。如果失败事件后紧跟来自同源地址的 4624，风险远高于单纯失败。

## 三、PowerShell 快速查询

最近一天的登录失败：

```powershell
$start = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
	LogName = "Security"
	Id = 4625
	StartTime = $start
} | Select-Object TimeCreated, Id, MachineName -First 50
```

查询登录成功、失败、特权会话和进程创建：

```powershell
Get-WinEvent -FilterHashtable @{
	LogName = "Security"
	Id = 4624, 4625, 4672, 4688
	StartTime = (Get-Date).AddHours(-6)
} | Sort-Object TimeCreated
```

导出日志时优先保留 EVTX：

```powershell
wevtutil epl Security C:\Evidence\Security.evtx
```

查询结果应至少保留：

- `TimeCreated`
- `EventRecordID`
- `TargetUserName`
- `LogonType`
- `IpAddress`
- `WorkstationName`
- `ProcessName`
- `Status` 与 `SubStatus`

## 四、一个排查案例

假设 SIEM 报告某运维账号连续登录失败：

```text
02:10:01 4625 adminops 10.10.8.23
02:10:03 4625 adminops 10.10.8.23
02:10:07 4624 adminops 10.10.8.23 LogonType=10
02:10:08 4672 adminops
02:11:20 4688 powershell.exe
```

分析顺序：

1. 询问账号本人是否在该时间操作；
2. 确认 `10.10.8.23` 是跳板机、终端还是未知地址；
3. 用登录 ID 关联 4624、4672 和 4688；
4. 检查 PowerShell 命令行、父进程和网络连接；
5. 搜索同一源地址登录过的其他账号和主机；
6. 若无法解释，禁用账号、吊销会话并隔离来源终端。

这个链条比“失败三次就告警”更准确，因为它体现了失败后成功、获得高权限并执行命令的连续行为。

## 五、容易产生误判的场景

- 服务账号密码修改后，旧服务持续产生 4625；
- 漏洞扫描或资产探测使用了无效凭据；
- 运维脚本通过网络登录多台主机；
- 远程 WMI 先产生一次失败、随后成功；
- NAT、堡垒机或代理使多个用户共享来源 IP；
- 时区不一致导致事件顺序看似异常。

## 值守检查清单

- 审核策略是否开启，日志容量是否足够；
- 关键服务器是否集中收集日志；
- 是否能查询账号、来源 IP、登录类型与失败状态；
- 高权限账号是否出现异常时间、异常来源或异常登录类型；
- 失败后成功是否有专门关联规则；
- 安全日志清除事件是否被监控；
- 4688 是否记录命令行。

## 本篇小结

Windows 登录日志分析的核心不是背事件 ID，而是围绕“账号—来源—登录类型—会话—后续进程”建立时间线。4625 提供尝试，4624 提供成功，4672 和 4688则帮助判断成功之后做了什么。

## 参考资料

- [Microsoft Learn：高级审核策略配置](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft Learn：事件 4625——账号登录失败](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft Sentinel：Windows 安全事件集合参考](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference)
