---
title: 护网初级蓝队学习笔记（五）：Wireshark 流量包快速研判
published: 2025-06-08
description: 从会话统计、显示过滤器、DNS 与 HTTP 线索到 TCP 流跟踪，整理 PCAP 快速研判步骤。
tags: [蓝队, Wireshark, PCAP, 流量分析, 网络安全]
category: 蓝队学习
draft: false
author: GGBoss
---

## 分析目标

拿到 PCAP 后，不应从第一帧开始逐包阅读。初级蓝队首先要回答：

- 哪些主机参与通信；
- 谁主动连接谁；
- 使用了哪些协议和端口；
- 是否存在异常 DNS、HTTP 请求、文件传输或周期外联；
- 流量是否完整，能否支撑结论。

Wireshark 的官方手册区分“捕获过滤器”和“显示过滤器”：前者决定抓什么，后者只决定已经捕获的数据如何展示。二者语法不同，不能混用。

## 一、快速分析顺序

### 1. 确认基本信息

先查看：

- `Statistics → Capture File Properties`
- `Statistics → Protocol Hierarchy`
- `Statistics → Endpoints`
- `Statistics → Conversations`

记录抓包开始和结束时间、数据包数量、丢包提示、主要 IP 和协议占比。会话列表按字节数、包数排序，常能快速发现大流量传输或长连接。

### 2. 确定内外网方向

根据资产清单识别内网网段，不能只依赖 RFC1918 地址。云环境、NAT、VPN 和容器网络可能改变真实方向。

```text
内部客户端 → 外部服务：通常是出站
外部地址 → 互联网暴露服务器：通常是入站
内部主机 → 多台内部主机：可能是运维，也可能是横向
```

### 3. 再进入具体协议

优先看 DNS、HTTP、TLS、SMB、SSH、RDP 和异常高端口，最后才跟踪具体会话。

## 二、常用显示过滤器

[Wireshark 显示过滤器手册](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) 说明，显示过滤器可以判断字段是否存在、比较字段和值，也能组合逻辑条件。

### IP 与端口

```text
ip.addr == 192.0.2.10
ip.src == 192.0.2.10
ip.dst == 198.51.100.20
tcp.port == 443
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### DNS

```text
dns
dns.flags.response == 0
dns.qry.name contains "example"
dns.flags.rcode != 0
```

### HTTP

```text
http.request
http.request.method == "POST"
http.response.code >= 400
http.host contains "example"
http.request.uri contains "upload"
```

### 异常与重传

```text
tcp.analysis.retransmission
tcp.analysis.lost_segment
tcp.analysis.flags
```

重传不必然是攻击，也可能是网络质量、抓包点或数据丢失问题。

## 三、DNS 研判

关注：

- 新注册或业务中从未出现的域名；
- 同一主机短时间查询大量随机子域；
- 大量 NXDOMAIN；
- 域名长度、熵值和查询频率异常；
- 查询后紧跟固定周期外联；
- 多台主机访问同一稀有域名。

一个基础筛选流程：

```text
dns.flags.response == 0
```

先导出查询名并统计频次，再针对可疑域名观察响应 IP、TTL、后续 TCP/TLS 会话。加密流量看不到内容时，DNS 仍可能提供基础设施线索。

## 四、HTTP 与文件线索

未加密 HTTP 可直接查看 Host、URI、User-Agent、状态码和正文：

1. 用 `http.request` 定位请求；
2. 检查 Host、URI、方法和 User-Agent；
3. 使用 `Follow → HTTP Stream` 或 `TCP Stream`；
4. 检查请求与响应是否匹配；
5. 在授权分析环境中导出对象并计算哈希。

可疑表现：

- WebShell 常见参数或极短 POST；
- 用户代理与业务程序不符；
- 响应体返回命令结果；
- 可执行文件、脚本或压缩包下载；
- 客户端向未知站点大体积上传；
- 同一 URI 高频、固定间隔访问。

不能只依据字符串下结论。运维接口、监控探针和 API 客户端也可能具备相似特征。

## 五、TShark 批量提取

提取 DNS 查询：

```bash
tshark -r evidence.pcapng -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

提取 HTTP 请求：

```bash
tshark -r evidence.pcapng -Y "http.request" \
  -T fields -e frame.time -e ip.src -e http.host \
  -e http.request.method -e http.request.uri
```

提取 TCP 会话：

```bash
tshark -r evidence.pcapng -q -z conv,tcp
```

批量结果适合统计，但关键结论仍需返回原始数据包验证。

## 六、证据和局限

PCAP 可能存在以下限制：

- 抓包开始前连接已经建立；
- 镜像口拥塞导致丢包；
- TLS 加密使应用内容不可见；
- NAT 隐藏原始终端；
- 网卡 offload 造成校验和看似错误；
- 只在单向链路抓包；
- 时间戳与主机日志不一致。

因此报告中应写清“观察到的事实”和“由于抓包范围无法确认的部分”。

## 我的 PCAP 研判模板

```text
时间范围：
抓包点与网络方向：
重点源/目标：
主要协议：
可疑会话：
DNS 线索：
HTTP/TLS 线索：
传输文件及 SHA256：
与主机日志的关联：
结论与置信度：
数据局限：
```

## 本篇小结

PCAP 分析应先统计、后过滤、再跟流，最后与主机和应用日志关联。一个异常数据包很少能独立证明入侵，稳定的会话时间线和多源证据才是蓝队报告的核心。

## 参考资料

- [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [Wireshark：Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark：wireshark-filter 手册](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
- [Wireshark：DNS 字段参考](https://www.wireshark.org/docs/dfref/d/dns.html)
