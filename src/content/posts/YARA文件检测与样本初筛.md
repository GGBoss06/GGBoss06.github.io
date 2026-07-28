---
title: 护网初级蓝队学习笔记（九）：YARA 文件检测与样本初筛
published: 2025-11-16
description: 学习 YARA 的 meta、strings、condition、PE 模块和规则测试方法，避免只靠单个字符串或文件哈希。
tags: [蓝队, YARA, 恶意样本, 文件检测, 应急响应]
category: 蓝队学习
draft: false
author: GGBoss
---

## YARA 的定位

YARA 用文本、十六进制字节、正则表达式和布尔条件描述文件或内存中的特征，常用于样本分类、落地文件排查和事件响应。官方文档指出，一条规则的核心是字符串集合与决定是否匹配的布尔表达式。

YARA 命中表示“文件满足规则条件”，不等于可以直接断言它是恶意软件。规则质量取决于特征选择、样本范围和误报测试。

## 一、规则基本结构

```yara
rule Suspicious_PE_Downloader_Lab
{
    meta:
        author = "GGBoss"
        description = "Training rule for a suspicious PE downloader"
        date = "2025-11-16"

    strings:
        $ua = "Mozilla/5.0" ascii
        $api1 = "URLDownloadToFile" ascii wide
        $api2 = "WinHttpOpen" ascii wide
        $cmd = "powershell -enc" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of ($api*) and
        ($ua or $cmd)
}
```

结构：

- `meta`：描述、作者、日期等，不参与匹配；
- `strings`：文本、十六进制或正则特征；
- `condition`：最终布尔逻辑。

[YARA 官方规则文档](https://yara.readthedocs.io/en/stable/writingrules.html) 说明，`condition` 始终必需，而不依赖字符串的规则可以省略 `strings`。

## 二、为什么不应只写一个字符串

低质量规则：

```yara
rule Bad_Rule
{
    strings:
        $a = "powershell"
    condition:
        $a
}
```

这会命中文档、脚本、日志和正常工具。改进方向：

1. 限制文件类型或结构；
2. 组合多个相对稳定特征；
3. 使用文件大小范围；
4. 选择恶意家族特有字符串或字节序列；
5. 排除已知正常样本；
6. 用多个版本的恶意样本验证。

哈希很精确，但文件改一个字节就会失效；宽泛字符串覆盖广，但误报高。YARA 的优势正是将多个不同强度的特征组合。

## 三、字符串类型和修饰符

文本：

```yara
$text = "example" ascii wide nocase
```

十六进制：

```yara
$hex = { 48 8B ?? ?? 48 85 C0 [2-6] 75 ?? }
```

正则：

```yara
$url = /https?:\/\/[a-z0-9.-]+\/[a-z0-9_\/.-]+/ nocase
```

常用修饰符：

- `ascii` / `wide`：ASCII 或宽字符；
- `nocase`：忽略大小写；
- `fullword`：完整单词；
- `xor`：匹配 XOR 变体；
- `base64` / `base64wide`：匹配 Base64 编码形式。

正则和过宽的 XOR/Base64 匹配可能影响性能，应尽量让特征具体。

## 四、使用 PE 模块增加结构约束

```yara
import "pe"

rule Unsigned_PE_With_Suspicious_Imports_Lab
{
    strings:
        $api1 = "VirtualAlloc"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 3 and
        2 of ($api*) and
        not pe.is_signed
}
```

模块让规则利用 PE 结构，而不只是在全文件搜索字符串。但“未签名 + 可疑 API”仍可能命中合法安全工具或开发样本，不能省略环境验证。

## 五、规则测试

语法检查和扫描：

```bash
yara -w rules.yar sample.bin
yara -r rules.yar ./samples/
```

显示命中字符串：

```bash
yara -s rules.yar sample.bin
```

测试集至少包含：

```text
malicious/
  家族的多个版本和变种
benign/
  系统文件、常用软件、开发工具
near-miss/
  与恶意样本使用相似库或字符串的正常程序
```

记录每次测试的真阳性、假阳性和漏报，规则逻辑变化后重新回归。

## 六、事件响应中的使用方式

从已确认样本提取稳定特征后：

1. 先在隔离样本库验证；
2. 扫描失陷主机的重点目录；
3. 在同类主机小范围狩猎；
4. 对命中文件保留路径、大小、时间和 SHA256；
5. 关联文件创建进程、下载来源和执行记录；
6. 调优后再扩大范围。

重点目录可能包括：

```text
Windows: Temp、AppData、ProgramData、Public、Web 根目录
Linux: /tmp、/var/tmp、/dev/shm、Web 根目录、用户启动目录
```

对大规模在线扫描，要评估 CPU、磁盘 IO 和业务影响。

## 七、规则治理

- 每条规则有唯一名称、作者、描述、样本依据和日期；
- 记录适用恶意家族与预期误报；
- 样本和规则使用受控权限；
- 不把敏感样本上传到未授权第三方；
- 规则修改进入版本控制；
- 过时规则标记而不是悄悄覆盖；
- 命中结果必须由分析员结合上下文复核。

## 本篇小结

YARA 规则不是“恶意字符串清单”，而是对文件特征的可解释组合。初级蓝队应从结构约束、多特征组合和测试集入手，确保规则既能命中已知样本，也能说明可能的误报边界。

## 参考资料

- [YARA 官方文档：Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA 官方文档首页与示例](https://yara.readthedocs.io/en/stable/)
- [YARA 官方文档：Modules](https://yara.readthedocs.io/en/stable/modules.html)
