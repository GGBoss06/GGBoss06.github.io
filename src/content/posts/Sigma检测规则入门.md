---
title: 护网初级蓝队学习笔记（八）：Sigma 检测规则入门
published: 2025-10-11
description: 学习 Sigma 规则的 logsource、detection、condition、误报说明与 ATT&CK 映射，并以登录失败检测为例。
tags: [蓝队, Sigma, SIEM, 检测工程, MITRE ATT&CK]
category: 蓝队学习
draft: false
author: GGBoss
---

## Sigma 是什么

Sigma 是用 YAML 描述日志检测逻辑的开放格式。它的目标不是绑定某一种 SIEM，而是让检测规则能够转换到不同查询后端。官方文档将规则分为三部分：

- metadata：标题、ID、状态、描述、参考、作者、标签等；
- logsource：规则针对什么日志；
- detection：搜索条件与组合逻辑。

根据 [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)，`title`、`logsource`、`detection` 是核心结构；规则 ID 通常使用 UUID，日期使用 ISO 8601。

## 一、从一条基础规则开始

下面检测 Windows 登录失败，仅作为语法学习：

```yaml
title: Windows Failed Logon
id: 2d9f3e74-52fa-4eb7-8c69-a6cd339fd326
status: test
description: Records failed Windows logons for subsequent correlation.
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
author: GGBoss
date: 2025-10-11
tags:
  - attack.credential_access
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
falsepositives:
  - User typing an incorrect password
  - Service account with an outdated stored password
level: low
```

它只识别单次失败登录，因此不应该直接定义为“爆破攻击”。

## 二、Detection 的组成

多个条件可以使用列表和字段修饰符：

```yaml
detection:
  selection_event:
    EventID: 4688
  selection_image:
    NewProcessName|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cli:
    CommandLine|contains:
      - 'EncodedCommand'
      - 'FromBase64String'
  condition: all of selection_*
```

常见修饰符：

- `contains`
- `startswith`
- `endswith`
- `re`
- `base64`
- `windash`
- `all`

字段名必须与实际日志管道一致。相同 Windows 事件进入不同 SIEM 后，可能被 ECS、ASIM 或自定义解析器映射成不同字段。规则能转换不代表无需适配。

## 三、单事件与关联规则

“5 分钟内同一来源对多个账号失败”是多事件行为，不能用一条普通事件匹配准确描述。[Sigma Meta Rules](https://sigmahq.io/docs/meta/) 支持相关规则的事件计数和分组：

```yaml
title: Multiple Failed Logons From One Source
status: test
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
level: medium
```

在真实环境中还要处理：

- NAT 或代理共享地址；
- 堡垒机集中运维；
- 扫描器与健康检查；
- 服务账号旧密码；
- 账号枚举与单账号爆破的差异。

## 四、ATT&CK 映射不能只看工具名

标签用于表达检测覆盖，例如：

```yaml
tags:
  - attack.execution
  - attack.t1059.001
```

映射应基于规则实际检测的行为，而不是因为规则中出现 `powershell.exe` 就声称覆盖所有 PowerShell 技术。还应参考 ATT&CK 要求的数据组件：进程创建、网络连接、脚本内容、文件或注册表等。

[MITRE ATT&CK Data Components](https://attack.mitre.org/datacomponents/) 对数据种类给出定义，可用于检查“规则想检测的行为”和“当前日志能提供的字段”是否匹配。

## 五、规则开发流程

```text
攻击/风险假设
  ↓
明确所需数据源与字段
  ↓
采集阳性、阴性样本
  ↓
编写 Sigma
  ↓
转换并验证目标 SIEM 查询
  ↓
回放历史数据
  ↓
小范围上线
  ↓
记录误报、漏报并调优
```

规则验收不只看“能否触发”，还要检查：

- 数据是否稳定进入；
- 字段解析是否正确；
- 查询性能是否可接受；
- 告警是否带足够上下文；
- 分析员能否按操作手册处置；
- 规则失效时是否有人发现。

## 六、误报与排除

错误做法：

```yaml
filter:
  User: administrator
```

这会把高价值账号全部排除。更稳妥的思路是组合：

- 已批准的管理终端；
- 已知运维时间窗；
- 指定脚本哈希或签名；
- 变更单编号；
- 预期父进程和命令行。

排除规则同样需要负责人、理由和过期时间。

## 七、规则文档应回答的问题

1. 要检测什么行为；
2. 为什么这个行为有风险；
3. 依赖哪些日志和字段；
4. 哪些正常业务会触发；
5. 命中后如何验证；
6. 哪些情况下会漏报；
7. 对应哪个 ATT&CK 技术；
8. 谁维护、何时复核。

## 本篇小结

Sigma 解决的是“如何结构化表达检测逻辑”，并不自动解决日志质量、字段映射和误报。初级蓝队写规则时，应从可验证的行为假设出发，先保证数据，再谈转换和覆盖率。

## 参考资料

- [Sigma 官方文档：Rules](https://sigmahq.io/docs/basics/rules.html)
- [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma 官方文档：Meta Rules 与关联](https://sigmahq.io/docs/meta/)
- [MITRE ATT&CK：Data Components](https://attack.mitre.org/datacomponents/)
