---
title: 护网初级蓝队学习笔记（四）：Linux auditd 审计与入侵排查
published: 2025-04-27
description: 整理 Linux Audit 日志结构、常用规则、ausearch 查询方法以及账号、文件和命令执行排查思路。
tags: [蓝队, Linux, auditd, 日志审计, 入侵排查]
category: 蓝队学习
draft: false
author: GGBoss
---

## Audit 能看到什么

Linux Audit 是内核级审计框架。它根据规则记录系统调用、文件访问、账号变化等安全相关事件，`auditd` 再把事件写入日志。常见位置是：

```text
/var/log/audit/audit.log
```

Red Hat 的 [系统审计文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/security_hardening/index) 强调，审计规则要围绕安全目标设计；示例规则并不等于完整、长期有效的基线。

## 一、先认识一组 Audit 事件

同一次行为可能产生多行记录，并通过相同的消息 ID 关联：

```text
type=SYSCALL msg=audit(1743000000.321:416): ...
type=EXECVE  msg=audit(1743000000.321:416): ...
type=CWD     msg=audit(1743000000.321:416): ...
type=PATH    msg=audit(1743000000.321:416): ...
```

- `SYSCALL`：系统调用、返回值、进程和身份；
- `EXECVE`：执行参数；
- `CWD`：进程当前目录；
- `PATH`：涉及的文件路径；
- `USER_AUTH` / `USER_LOGIN`：认证与登录；
- `USER_ACCT`：账号检查；
- `CONFIG_CHANGE`：审计配置变化。

关键字段：

- `pid` / `ppid`：当前与父进程；
- `uid`：实际用户 ID；
- `euid`：有效用户 ID；
- `auid`：最初登录用户，使用 sudo 后仍便于追踪；
- `exe`：可执行文件；
- `success` 与 `exit`：调用是否成功；
- `key`：自定义审计规则标签。

## 二、临时规则与持久化规则

查看规则：

```bash
auditctl -l
```

临时监控 `/etc/passwd` 的写入和属性变化：

```bash
auditctl -w /etc/passwd -p wa -k identity_change
```

监控账号相关文件：

```bash
auditctl -w /etc/group -p wa -k identity_change
auditctl -w /etc/shadow -p wa -k identity_change
auditctl -w /etc/sudoers -p wa -k privilege_change
auditctl -w /etc/sudoers.d/ -p wa -k privilege_change
```

临时规则重启后会消失。RHEL 系列通常把持久化规则写入：

```text
/etc/audit/rules.d/*.rules
```

再使用：

```bash
augenrules --load
```

修改前必须在测试环境验证，错误或过宽规则可能造成大量日志和性能压力。

## 三、常用查询

按规则标签查询：

```bash
ausearch -k identity_change -i
```

按可执行程序查询：

```bash
ausearch -x /usr/bin/sudo -i
```

查询当天失败事件：

```bash
ausearch --start today --success no -i
```

按用户审计 ID 查询：

```bash
ausearch -ua 1000 -i
```

生成汇总：

```bash
aureport --auth
aureport --login
aureport --executable
```

`-i` 会把 UID、系统调用号等解释成人类可读形式，适合分析；保全证据时仍应保存未经转换的原始日志。

## 四、护网中的三类排查

### 1. 可疑账号与提权

重点检查：

```bash
last -ai
lastb -ai
getent passwd
sudo -l
```

结合 Audit 搜索：

- `/etc/passwd`、`/etc/shadow` 是否被修改；
- 是否新建 UID 0 账号；
- `sudoers` 是否增加免密授权；
- 登录用户与最终执行 root 命令的 `auid` 是否一致；
- 是否出现来源异常的 SSH 登录。

### 2. 持久化

常见检查位置：

```text
/etc/cron*
/var/spool/cron/
/etc/systemd/system/
/usr/lib/systemd/system/
~/.ssh/authorized_keys
/etc/rc.local
```

应记录文件时间、所有者、哈希和关联进程，不能只凭文件名判断恶意。

### 3. Web 服务器异常命令

Web 服务用户通常不应频繁启动 shell、下载器或系统管理工具。可关注：

```text
auid 为空或为 Web 服务身份
exe = /bin/sh、/bin/bash、curl、wget、python
父进程 = nginx、apache2、httpd、php-fpm、java
```

若 Web 进程产生 shell，应立即关联 Web 访问日志、文件落地和网络连接，确认是否为命令执行漏洞。

## 五、日志可靠性也要监控

攻击者获得高权限后可能停止审计、修改规则或删除日志。因此还要检查：

```bash
systemctl status auditd
auditctl -s
journalctl -u auditd
```

同时关注：

- `CONFIG_CHANGE`；
- 日志轮转是否正常；
- 磁盘是否已满；
- 审计 backlog 是否丢事件；
- 主机日志是否已集中转发。

本地日志只能说明“主机当前留下了什么”，集中日志更能抵抗本机被篡改。

## 六、证据保全注意事项

1. 统一并记录系统时区；
2. 先复制日志、计算哈希，再进行大量查询；
3. 不直接在原始证据文件上修改；
4. 记录每条命令、操作者和执行时间；
5. 不因发现可疑文件就立即删除；
6. 将主机日志与防火墙、WAF、DNS、EDR 时间线对齐。

## 本篇小结

Audit 的优势是把“哪个登录用户通过哪个进程对什么文件执行了什么系统调用”串联起来。初级蓝队应先掌握身份变化、特权配置、持久化路径和 Web 进程异常执行，再逐步扩充规则，避免一次性开启过量审计。

## 参考资料

- [Red Hat Enterprise Linux 9：Security hardening / Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/security_hardening/index)
- [Red Hat Enterprise Linux 7：System Auditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [MITRE ATT&CK：Data Components](https://attack.mitre.org/datacomponents/)
