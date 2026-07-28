---
title: 护网初级蓝队学习笔记（六）：Zeek 网络日志关联分析
published: 2025-07-19
description: 学习 Zeek 的 conn、dns、http、ssl、files 等常见日志，并使用 uid 串联一次网络会话。
tags: [蓝队, Zeek, 网络日志, 威胁狩猎, SOC]
category: 蓝队学习
draft: false
author: GGBoss
---

## Zeek 和抓包工具的区别

Wireshark 适合查看数据包细节，Zeek 更适合把流量转换为结构化日志。它不是简单地告诉我“某条规则命中”，而是记录连接、DNS、HTTP、TLS、文件等协议活动，便于检索、统计和关联。

Zeek 官方的 [Common Logs](https://docs.zeek.org/en/current/reference/logs/index.html) 列出了常用日志，包括：

- `conn.log`：连接元数据；
- `dns.log`：DNS 查询与响应；
- `http.log`：HTTP 请求与响应；
- `ssl.log`：TLS 会话；
- `x509.log`：证书信息；
- `files.log`：网络传输文件；
- `smtp.log`：邮件会话；
- `ssh.log`：SSH 握手与认证结果；
- `notice.log`：Zeek 产生的通知；
- `weird.log`：协议解析中的异常现象；
- `capture_loss.log`：抓包丢失情况。

## 一、先读懂 conn.log

`conn.log` 是网络调查的入口。常见字段：

| 字段 | 含义 |
| --- | --- |
| `ts` | 会话时间 |
| `uid` | Zeek 会话唯一标识 |
| `id.orig_h` / `id.orig_p` | 发起方 IP 和端口 |
| `id.resp_h` / `id.resp_p` | 响应方 IP 和端口 |
| `proto` / `service` | 传输层协议和识别出的服务 |
| `duration` | 会话持续时间 |
| `orig_bytes` / `resp_bytes` | 双向有效载荷字节 |
| `conn_state` | 连接状态 |
| `history` | TCP 状态历史简写 |

`uid` 是最重要的关联键。相同会话在 `conn.log`、`http.log`、`ssl.log` 和 `files.log` 中通常共享它。

## 二、基础命令行查询

Zeek 日志默认是制表符分隔。快速筛选 IP：

```bash
grep -F "192.0.2.25" conn.log
```

使用 `zeek-cut` 按字段读取更稳妥：

```bash
cat conn.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p service duration
```

统计目标端口：

```bash
cat conn.log | zeek-cut id.resp_p | sort | uniq -c | sort -nr | head
```

按某个 UID 串联日志：

```bash
uid="CExample123"
grep -F "$uid" conn.log dns.log http.log ssl.log files.log
```

分析生产日志时应避免用简单空格切列，因为字段内容和缺失值会导致偏移。

## 三、DNS 狩猎思路

`dns.log` 常看：

- `query`：查询名；
- `qtype_name`：A、AAAA、TXT 等；
- `rcode_name`：响应状态；
- `answers`：答案；
- `TTLs`：缓存时间；
- `rejected`：请求是否被拒绝。

基础排查：

```bash
cat dns.log | zeek-cut id.orig_h query qtype_name rcode_name answers
```

可疑特征包括：

1. 同一主机查询大量随机子域；
2. NXDOMAIN 比例突然上升；
3. 极长子域或高频 TXT 查询；
4. 域名刚出现就产生固定间隔外联；
5. 多台主机访问同一罕见域名。

这些是狩猎线索，不是定罪条件。CDN、EDR、浏览器遥测和软件更新也会产生复杂域名。

## 四、HTTP、TLS 与文件日志关联

未加密 HTTP 可以在 `http.log` 中看到：

- `host`
- `uri`
- `method`
- `user_agent`
- `status_code`
- `request_body_len`
- `response_body_len`

TLS 下通常看不到 URI，但 `ssl.log` 和 `x509.log` 仍可提供服务器名称、TLS 版本、证书主题和有效期等元数据。

如果 `files.log` 出现文件：

1. 记录 `fuid`、`uid`、MIME、大小和哈希；
2. 用 `uid` 回到连接及 HTTP 日志；
3. 确认哪台主机从哪里获取文件；
4. 检索相同哈希是否在其他主机出现；
5. 在隔离分析环境中处理导出的文件。

## 五、用字节比发现可能的数据外传

从 `conn.log` 观察：

```text
orig_bytes 远大于 resp_bytes
+ 外部目标稀有
+ 会话持续时间长或周期重复
+ 发起主机不应大量上传
= 值得进一步调查
```

MITRE ATT&CK 把网络流量区分为流量元数据和完整内容。其 [Data Components](https://attack.mitre.org/datacomponents/) 指出，流量元数据适合分析源、目的、端口、时间和流量大小，而完整内容才包含协议头与载荷。Zeek 日志主要是元数据和协议解析结果，不能替代所有 PCAP。

## 六、一次简单时间线

```text
09:30:00 dns.log
客户端查询 update-example.test

09:30:01 conn.log / ssl.log
客户端连接新解析 IP 的 443，持续 300 秒

09:35:10 conn.log
再次连接同一目标，间隔接近固定

09:40:12 conn.log
第三次连接，出站字节明显大于入站
```

接下来应检查：

- 终端上由哪个进程发起连接；
- 域名在组织中的首次出现时间；
- 其他主机是否有相同行为；
- TLS 证书与 SNI 是否稳定；
- 是否存在对应文件、账号或进程告警。

网络侧只能证明“发生了通信”，主机侧才能更好回答“哪个进程为什么通信”。

## 七、传感器健康不能忽略

结论之前检查：

- `capture_loss.log` 是否丢包；
- `reporter.log` 是否报错；
- 时间同步是否正常；
- 监控链路是否双向可见；
- 日志轮转和存储是否完整；
- 网络升级后协议解析是否异常。

传感器丢包严重时，“没看到恶意流量”不能作为“没有恶意流量”的证据。

## 本篇小结

Zeek 分析的核心是从 `conn.log` 找会话，用 `uid` 关联 DNS、HTTP、TLS 和文件，再与端点进程关联。结构化日志适合大范围搜索，PCAP 适合深入验证，两者结合更适合护网研判。

## 参考资料

- [Zeek 官方文档：Common Logs](https://docs.zeek.org/en/current/reference/logs/index.html)
- [MITRE ATT&CK：Data Components](https://attack.mitre.org/datacomponents/)
- [MITRE ATT&CK：基于文件传输协议的 C2 检测策略](https://attack.mitre.org/detectionstrategies/DET0416/)
