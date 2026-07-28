---
title: 护网初级蓝队学习笔记（七）：Suricata 规则编写与告警调优
published: 2025-08-30
description: 从 Suricata 规则结构、HTTP 粘性缓冲区、sid 与 rev 管理，到误报验证和规则上线流程。
tags: [蓝队, Suricata, IDS, 规则编写, 网络检测]
category: 蓝队学习
draft: false
author: GGBoss
---

## 先理解规则的三个部分

Suricata 官方 [Rules Format](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html) 将一条规则拆成：

1. action：匹配后执行什么；
2. header：协议、地址、端口和方向；
3. options：更具体的匹配条件与元数据。

示例：

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"LAB Suspicious PowerShell String in HTTP URI";
  flow:established,to_server;
  http.uri;
  content:"powershell"; nocase;
  classtype:trojan-activity;
  sid:1000001;
  rev:1;
)
```

为便于阅读，示例分了多行；实际加载前要按 Suricata 语法检查。这里只用于授权实验环境。

## 一、逐段解释

### Action

- `alert`：产生告警；
- `pass`：匹配后停止进一步检查；
- `drop`：IPS 模式下丢弃并告警；
- `reject`：拒绝连接并返回 RST 或 ICMP。

护网初期的新规则应先使用 `alert` 观察误报。未充分验证就改为 `drop`，可能造成业务中断。

### Header

```text
alert http $HOME_NET any -> $EXTERNAL_NET any
```

表示检查从内部网络发往外部网络的 HTTP 流量。`->` 有方向，`<>` 表示双向。`HOME_NET` 配错会让规则方向和资产边界全部失真。

### Options

- `msg`：告警名称；
- `flow`：连接方向与状态；
- `http.uri`：切换到规范化 HTTP URI 缓冲区；
- `content`：匹配内容；
- `nocase`：忽略大小写；
- `classtype`：事件类别；
- `sid`：规则唯一编号；
- `rev`：规则修订版本。

## 二、为什么要使用协议缓冲区

直接在原始包中搜索字符串，容易把请求头、响应或其他字段混在一起。Suricata 的 HTTP 关键字可以限制检测位置：

```text
http.method
http.uri
http.host
http.user_agent
http.request_body
http.response_body
```

例如只检查 POST 到特定路径：

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"LAB POST to Sensitive Upload Endpoint";
  flow:established,to_server;
  http.method; content:"POST";
  http.uri; content:"/upload"; startswith;
  sid:1000002;
  rev:1;
)
```

业务确实存在 `/upload` 时，这条规则会有大量正常告警，必须继续增加来源、参数、内容或响应行为等上下文。

## 三、检测行为而不是只堆 IOC

IOC 规则：

```text
alert ip any any -> 203.0.113.10 any (
  msg:"LAB Known Malicious Destination";
  sid:1000003;
  rev:1;
)
```

优点是明确、快速；缺点是 IP 改变后立即失效，还可能命中共享云地址。

行为规则更关注：

- 异常协议字段；
- 特定工具的稳定请求特征；
- Web 攻击的参数组合；
- 出站连接的方向、状态和内容；
- 文件类型与传输行为不一致。

成熟检测通常组合行为、资产上下文和威胁情报，而不是只靠一个字符串。

## 四、规则验证流程

### 1. 语法检查

```bash
suricata -T -c /etc/suricata/suricata.yaml
```

### 2. 离线回放 PCAP

```bash
suricata -r sample.pcap -c /etc/suricata/suricata.yaml \
  -l ./suricata-output
```

### 3. 查看 EVE JSON

```bash
jq 'select(.event_type == "alert")' suricata-output/eve.json
```

### 4. 同时做阳性与阴性测试

- 阳性样本：规则应该命中；
- 阴性样本：相似的正常业务不应命中；
- 边界样本：大小写、编码、分片、不同方向和不同端口。

### 5. 小范围灰度

先在镜像流量或少量传感器运行，统计告警量、重复率和业务来源，再推广。

## 五、误报调优记录

每次调整至少写下：

```text
规则 SID / REV：
检测目标：
数据来源：
已验证样本：
误报来源：
本次修改：
修改依据：
可能漏报：
负责人：
复核日期：
```

不要为了“清空告警”把条件排除得过宽。例如排除整个办公网段，可能让攻击者只需进入办公网就绕过检测。

## 六、告警研判

一条 Suricata 告警至少关联：

- 五元组与流方向；
- 告警前后同会话数据；
- HTTP Host、URI、状态码；
- DNS 查询；
- 目标资产和业务；
- 同源地址对其他资产的行为；
- 端点上的进程、文件与登录日志。

IDS 告警代表规则条件匹配，不等于攻击成功。若 HTTP 攻击之后出现 Web 服务进程创建 shell、文件落地或异常外联，才能提高事件置信度。

## 七、规则维护

- 本地规则使用独立 SID 范围，避免与外部规则冲突；
- 逻辑变化后增加 `rev`；
- 定期删除失效 IOC；
- 每次更新先执行 `-T`；
- 监控规则加载失败和传感器丢包；
- 保存规则来源、适用版本和授权信息；
- 生产规则变更进入版本控制和审批。

## 本篇小结

Suricata 规则的难点不在语法，而在准确描述检测目标、选择正确协议缓冲区，并用真实业务流量验证。对初级蓝队来说，一条经过样本测试、能解释误报和漏报边界的规则，比大量未经验证的规则更有价值。

## 参考资料

- [Suricata 8.0.3：Rules Format](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [Suricata 最新版官方规则文档](https://docs.suricata.io/en/latest/rules/)
- [MITRE ATT&CK：Network Traffic Data Components](https://attack.mitre.org/datacomponents/)
