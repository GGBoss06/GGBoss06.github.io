---
title: 中国民航大学校赛
published: 2026-06-01
description: 校赛部分题目的wp喵
image: https://cauc-csa.org.cn/img/other/logo.png
tags: [CTF,Crypto]
category: writeup
draft: false
author: GGBoss
---



## msbexp

### 解题人：GGBoss

### 题目分析：

加密就是标准 RSA，但加密完又多给了一个东西：

```python
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
c = pow(m, e, n)

print("Oh, it isn't secure enough!")

unknown_bits = 176
p_high = p >> unknown_bits
print(f"p_high = {p_high}")
```

就是把 $p$ 右移 176 bit 给出来了，等于 $p$ 的高 336 bit 已知，低 176 bit 未知。

#### 找到问题：

$p$ 的高位泄漏，Coppersmith 小根经典题。

设 $p_0 = p_{\text{high}} \ll 176$（已知高位左移对齐），未知部分为 $x$，那 $p = p_0 + x$，$0 \le x < 2^{176}$。

因为 $p \mid n$，所以 $p_0 + x \equiv 0 \pmod{p}$，即 $f(x) = x + p_0 \equiv 0 \pmod{p}$。

Coppersmith 对 $\beta = 0.5$（$p \approx \sqrt{n}$ 的情况）能恢复的上限大约是 $\frac{1}{2}\log_2(p) \approx 256$ bit。本题才未知 176 bit，远小于 256，稳出。

### 解题：

直接 SageMath 一把梭：

```sage
n = 144942568570520760344975213747339526330558125405751760815218714790129581899539855507779731514155363175962832550287561107379443214068529639687201561312399929710310218554040093575352234093234654518648899126351428985332001556506045900517668826782576693338273139701420948994708181848034714521238310081921644836099
e = 65537
c = 48807303788145958081081286306174828454603346687309906163957230365484897050230763655239128800610757395663379868082721508504996654617846593860047807159667772171984439701963794332662867918550299931770442848887303627897291230804191851080390903398284764173548400182992995457989012060456866412999861320681406006089
p_high = 123558288396587920683511335623810078636196371954000748361220942037486333112716568038290271067889295906
unknown_bits = 176

p0 = p_high << unknown_bits

PR.<x> = PolynomialRing(Zmod(n))
f = x + p0

roots = f.small_roots(X=2^unknown_bits, beta=0.49)
print("roots =", roots)

x0 = int(roots[0])
p = gcd(p0 + x0, n)
q = n // p

phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
m = pow(c, int(d), n)

print("flag =", bytes.fromhex(hex(int(m))[2:]))
```

#### 解释一下：

`small_roots` 两个参数：

- `X=2^176`：未知部分上界
- `beta=0.49`：$p$ 大约是 $n^{0.5}$，取0.49留点余量

跑出来：

```
roots = [68066552865826479698806060393318465425270622019467337]
```

$x_0$ 拿到了，$p = p_0 + x_0$，然后常规 RSA 解密就完事了。

```
AUVCTF{224fe181cc1e1baf57f2a6c1264b615b0594aaaee6e51a515526b7513e2f050a}
```





---



## LWE

### 解题人：GGBoss

### 题目分析：

加密逻辑很直接：

```python
p = getPrime(31)      # 小素数
r = getPrime(96)      # 大素数
q = p * r             # q = p * r，复合模数

secret = [random.choice([-1, 0, 1]) for _ in range(n)]  # n=36
error_bound = 3

for _ in range(m):    # m=64
    row = [random.randrange(q) for _ in range(n)]
    err = random.randint(-3, 3)
    lift = random.randrange(r)
    b_i = (sum(a * s for a, s in zip(row, secret)) + err + p * lift) % q
```

每个样本：$b_i \equiv \mathbf{a}_i \cdot \mathbf{s} + e_i + p \cdot l_i \pmod{q}$

flag 用`shake_256(bytes(x+1 for x in secret))`做密钥流异或加密，所以只要恢复secret就行。

#### 找到问题：

一眼看到 $q = p \times r$，复合模数，而且 $p$ 才 31 bit。这就很不对劲了——两边取模 $p$：

$$b_i \equiv \mathbf{a}_i \cdot \mathbf{s} + e_i + p \cdot l_i \pmod{p}$$

$p \cdot l_i \equiv 0 \pmod{p}$ 直接没了，变成：

$$b_i \equiv \mathbf{a}_i \cdot \mathbf{s} + e_i \pmod{p}$$

标准LWE，但模数从 127 bit 降到了 31 bit。secret 只有 $\{-1,0,1\}$，误差才 $[-3,3]$，方程数 64 大于未知数 36，格攻击随便打。

### 解题：

#### 拿到 p

```python
q = 153768266796549665701990292479082929013
p = min(int(f[0]) for f in factor(q))
```

直接分解 $q$，小的那个因子就是 $p$。

#### 降维

```python
A = A.apply_map(lambda x: x % p)
b = vector(ZZ, [int(x) % p for x in b])
```

全部模 $p$，把 LWE 拉到小模数下。

#### 构格 LLL

取 $k = \min(n+5, m) = 41$，构造格矩阵 $M$（维度 $(n+k+1) \times (n+k+1)$）：

$$M = \begin{pmatrix} I_n & A^T_{[:k]} & \mathbf{0} \\ \mathbf{0}_{k \times n} & p \cdot I_k & \mathbf{0} \\ \mathbf{0}_{1 \times n} & \mathbf{b}_{[:k]}^T & W \end{pmatrix}$$

也就是：

$$M = \begin{pmatrix} 1 & & & A_{0,0} & A_{1,0} & \cdots & A_{k-1,0} & 0 \\ & 1 & & A_{0,1} & A_{1,1} & \cdots & A_{k-1,1} & 0 \\ & & \ddots & \vdots & \vdots & & \vdots & \vdots \\ & & & 1 & A_{0,n-1} & \cdots & A_{k-1,n-1} & 0 \\ & & & p & & & & 0 \\ & & & & p & & & 0 \\ & & & & & \ddots & & \vdots \\ & & & & & & p & 0 \\ & & & b_0 & b_1 & \cdots & b_{k-1} & W \end{pmatrix}$$

三块行：

前 $n$ 行：对角 1，右上填 $A^T$

中间 $k$ 行：对角 $p$

最后一行：填 $b$，尾巴挂个 $W = \lfloor\sqrt{n}\rfloor = 6$

#### 代码：

```python
k = min(n + 5, m)   # 41
W = round(sqrt(n))   # 6
M = Matrix(ZZ, n + k + 1, n + k + 1)

for j in range(n):
    M[j, j] = 1
    for i in range(k):
        M[j, n + i] = int(A[i, j])

for i in range(k):
    M[n + i, n + i] = p
    M[n + k, n + i] = int(b[i])

M[n + k, -1] = W
```

如果 $\mathbf{s}$ 是正确的 secret，那 $\mathbf{a}_i \cdot \mathbf{s} + e_i \equiv b_i \pmod{p}$，存在整数 $c_i$ 使得 $\mathbf{a}_i \cdot \mathbf{s} - p \cdot c_i + b_i = -e_i$。做行向量的线性组合 $\mathbf{v} = \sum_{j} s_j \cdot \text{row}_j - \sum_{i} c_i \cdot \text{row}_{n+i} + \text{row}_{n+k}$：

- 前 $n$ 分量就是 $s_0, \ldots, s_{n-1}$
- 中间 $k$ 分量变成 $-e_0, \ldots, -e_{k-1}$
- 尾巴是 $W$

所以 $\mathbf{v} = (s_1, \ldots, s_n, -e_0, \ldots, -e_{k-1}, W)$，很短（$s_j \in \{-1,0,1\}$，$e_i \in [-3,3]$），LLL一跑就出来了。

#### 筛结果

```python
for row in M.LLL():
    if abs(row[-1]) != W:
        continue
    t = -1 if row[-1] > 0 else 1
    s = [t * int(row[j]) for j in range(n)]
    if not all(x in (-1, 0, 1) for x in s):
        continue
    if all(abs(c(int(b[i] - sum(A[i,j]*s[j] for j in range(n))), p)) <= bound
           for i in range(m)):
        secret = s
        break
```

过滤条件：

1. 最后一列绝对值=$W$（标记列，确定符号）
2. 前 $n$ 个分量都在 $\{-1, 0, 1\}$
3. 对所有 64 个方程验证误差 $\leq 3$

中心化取模：

```python
def c(x, p):
    x %= p
    return x if x <= p // 2 else x - p
```

#### 出 flag

```python
stream = hashlib.shake_256(bytes(x + 1 for x in secret)).digest(len(ct))
flag = bytes(a ^ b for a, b in zip(ct, stream))
```

```
AUVCTF{f0ea2a3a2ff883862a3c5c4da19b95797f8343131012d4dcffa4c252dab6a60e}
```



### exp：

```sage
import json, hashlib

def c(x, p):
    x %= p
    return x if x <= p // 2 else x - p

D = json.load(open("c:\\Users\\闫博泉\\Desktop\\Python\\2026校赛\\lwe.json", "r", encoding="utf-8"))
n, m, q = D["n"], D["m"], D["q"]
A = Matrix(ZZ, D["A"])
b = vector(ZZ, D["b"])
ct = bytes.fromhex(D["ciphertext"])
bound = D["error_bound"]

p = min(int(f[0]) for f in factor(q))
A = A.apply_map(lambda x: x % p)
b = vector(ZZ, [int(x) % p for x in b])

k = min(n + 5, m)
W = round(sqrt(n))
M = Matrix(ZZ, n + k + 1, n + k + 1)

for j in range(n):
    M[j, j] = 1
    for i in range(k):
        M[j, n + i] = int(A[i, j])

for i in range(k):
    M[n + i, n + i] = p
    M[n + k, n + i] = int(b[i])

M[n + k, -1] = W

for row in M.LLL():
    if abs(row[-1]) != W:
        continue

    t = -1 if row[-1] > 0 else 1
    s = [t * int(row[j]) for j in range(n)]

    if not all(x in (-1, 0, 1) for x in s):
        continue

    if all(abs(c(int(b[i] - sum(A[i, j] * s[j] for j in range(n))), p)) <= bound for i in range(m)):
        secret = s
        break

stream = hashlib.shake_256(bytes(x + 1 for x in secret)).digest(len(ct))
flag = bytes(a ^^ b for a, b in zip(ct, stream))
print(flag.decode())

```



---



## MIKU~ Writeup

### 解题人：GGBoss

M、I、K、U分别代表00 01 10 11

替换转换：

```
0100011101000110011011110100111101000101010001010011100101010001010011010100010100111001010001100111101001010111010011010111010101001010001100110100011000110011010000010100011101000101001100000100001100110000011011110110011001000011001100010100100101101100010011100011000100111001010000110100111001010011010100100110001101000001010110100011110100111101
```

再逆到字符串

```
GFoOEE9QME9FzWMuJ3F3AGE0C0ofC1IlN19CNSRcAZ==
```

![](https://ggboss06.oss-cn-beijing.aliyuncs.com/image-20260531203920484.png)

反转：注意是埃特巴什码的镜像，不是字符串对称

```
TUlLVV9JNV9UaDNfQ3U3ZTV0X0luX1RoM19XMHIxZA==
```

![](https://ggboss06.oss-cn-beijing.aliyuncs.com/image-20260531204035971.png)

解base64

```
MIKU_I5_Th3_Cu7e5t_In_Th3_W0r1d
```

```
A∪VCTF{MIKU_I5_Th3_Cu7e5t_In_Th3_W0r1d}
```



---



## Nonce

### 解题人：GGBoss

题目只给了一个 ELF 64-bit 的 stripped 二进制，没有任何源码。

### 题目分析：

#### 跑一下

先跑起来看看：

![](https://ggboss06.oss-cn-beijing.aliyuncs.com/image-20260531234913415.png)

菜单五个选项：

- 选 1 输出 `{"p":"14564401787003760479","q":"7282200893501880239","g":"4","y":"4871897555783532952"}`，这是公钥
- 选 2 输入消息能签名，但输 `role=admin` 直接回 `denied`
- 选 4 要拿 flag，得提供消息和签名，消息得是 `role=admin;uid=0`
- 选 5 诊断接口，输出 `{"hmac":"...","rsa":"..."}`

sign 不给签 admin，get_flag 要 admin 的签名。拿到私钥就能伪造。

#### strings

strings一扫：

![](https://ggboss06.oss-cn-beijing.aliyuncs.com/image-20260531235128159.png)

是离散对数的签名系统，有 P/Q/G/Y 四个参数，签名格式 `(msg, R, s)`，get_flag 要求 `msg == "role=admin;uid=0"`。光看字符串分不清 Schnorr 还是 DSA，得看 verify 函数。

#### 私钥怎么来的

IDA打开看伪代码（下面不截图了太累了直接复制了）：

![](https://ggboss06.oss-cn-beijing.aliyuncs.com/image-20260531235623095.png)

```c
v3 = getenv("TEAM_SECRET");
v4 = getenv("FLAG");

// FNV-1a hash TEAM_SECRET
v9 = 0x453046F527D251C2LL;
do {
    v10 = (unsigned __int8)*v7++;
    v9 = 0x100000001B3LL * (v10 ^ v9);
} while ( v7 != (char *)v8 );

// 私钥 X = hash % (Q-2) + 2
v11 = v9 % 0x650F9321403637ADLL + 2;
qword_4150 = v11;   // 私钥 X

// 同样 FNV-1a hash TEAM_SECRET（不同初始值）→ session_hash
v15 = 0x5A2A41F336C248B2LL;
do {
    v16 = (unsigned __int8)*v14++;
    v15 = 0x100000001B3LL * (v16 ^ v15);
} while ( v13 != (unsigned __int8 *)v14 );
qword_4140 = v15;   // session_hash，sign 函数要用

// Y = G^X mod P
// ... 快速幂循环 ...
qword_4148 = v21;   // 公钥 Y
```

私钥 X = FNV1a(TEAM_SECRET) % (Q-2) + 2，从环境变量导出。不知道 TEAM_SECRET 所以拿不到 X，但 Y 和 P 我们知道，P 才 64 bit。

#### 公钥输出

```c
printf(
    "{\"p\":\"%llu\",\"q\":\"%llu\",\"g\":\"%llu\",\"y\":\"%llu\"}\n",
    0xCA1F2642806C6F5FLL,   // P
    0x650F9321403637AFLL,   // Q
    4LL,                     // G
    qword_4148);             // Y
```

拿到公钥：

- $P = \texttt{0xCA1F2642806C6F5F} = 14564401787003760479$（64 bit）
- $Q = \texttt{0x650F9321403637AF} = 7282200893501880239$（63 bit）
- $G = 4$
- $Y = 4871897555783532952$

P才64bit，正常Schnorr/DSA的P至少2048bit，群太小，DLP可解。

#### sign 函数

```c
if ( strstr(s, "role=admin") || strstr(s, "admin=true") ) {
    puts("denied");
}
else {
    // ① 确定性派生 nonce：session_hash ^ FNV_OFFSET → FNV-1a(msg) + CRC-16
    v42 = qword_4140 ^ 0x14650FB0739D0383LL;
    do {
        v45 = (unsigned __int8)*v43++;
        v42 = 0x100000001B3LL * (v45 ^ v42);
    } while ( v44 != v43 );
    // CRC-16 ...
    v50 = (v46 | (unsigned __int64)v47) % 0x650F9321403637AFLL;
    if ( !v50 ) v50 = 1LL;

    // ② R = G^nonce_r mod P
    // ③ challenge e = FNV-1a(R, basis=0x85E77CD426DB34A2) ^ FNV_OFFSET → FNV-1a(msg) % Q
    v57 = 0x85E77CD426DB34A2LL;
    do {
        v58 = (unsigned __int8)*v56++;
        v57 = 0x100000001B3LL * (v58 ^ v57);
    } while ( v56 != v69 );
    v59 = v57 ^ 0x14650FB0739D0383LL;
    do {
        v62 = (unsigned __int8)*v60++;
        v59 = 0x100000001B3LL * (v59 ^ v62);
    } while ( v61 != v60 );

    // ④ s = (nonce_r + X * e) mod Q
    v63 = sub_1EB0(qword_4150 * (v59 % Q), ..., Q, 0);
    v64 = sub_1EB0(v50 + v63, ..., Q, 0);
}
```

Schnorr 签名：$R = G^k \bmod P$，$e = H(R, \text{msg})$，$s = k + Xe \bmod Q$，验证 $G^s = G^{k+Xe} = G^k \cdot G^{Xe} = R \cdot Y^e \pmod{P}$。

nonce 是确定性的（FNV-1a + CRC-16 从 msg 派生），但不知道 session_hash 所以没法利用，得走 DLP。

#### verify 函数——sub_1C00

```c
_BOOL8 __fastcall sub_1C00(const char *a1, unsigned __int64 a2, unsigned __int64 a3)
{
  // FNV-1a hash R 的 8 字节（小端序，R 存到栈上 v25 = a2）
  v5 = 0x85E77CD426DB34A2LL;
  v7 = (__int64 *)&v25;
  do {
    v8 = *(unsigned __int8 *)v7;
    v7 = (__int64 *)((char *)v7 + 1);
    v5 = 0x100000001B3LL * (v8 ^ v5);
  } while ( &v26 != (char *)v7 );  // 8字节结束

  // XOR FNV_OFFSET
  v9 = v5 ^ 0x14650FB0739D0383LL;

  // FNV-1a hash msg
  if ( v6 ) {
    v10 = &a1[v6];
    do {
      v11 = *(unsigned __int8 *)a1++;
      v9 = 0x100000001B3LL * (v9 ^ v11);
    } while ( v10 != a1 );
  }

  // e = hash % Q
  v12 = v9 % 0x650F9321403637AFLL;

  // G^s mod P（快速幂，base=4, exponent=a3=s, modulus=P）
  // IDA 反编译的快速幂很乱（循环展开+goto），本质就是 powmod(4, s, P)
  // 结果存 v23

  // Y^e mod P（快速幂，base=qword_4148=Y, exponent=v12=e, modulus=P）
  // 结果存 v20

  // 比较
  return v23 == sub_1EB0(v20 * a2, ((unsigned __int64)v20 * (unsigned __int128)a2) >> 64,
                          0xCA1F2642806C6F5FLL, 0LL);
  // G^s == (Y^e * R) mod P，即 G^s ≡ R · Y^e (mod P)
}
```

验证方程 $G^s \equiv R \cdot Y^e \pmod{P}$，challenge 输入了 R，这是 Schnorr 不是 DSA：

- Schnorr：$G^s \equiv R \cdot Y^e$，challenge 带 R
- DSA：$r \equiv (G^{s^{-1}e} \cdot Y^{s^{-1}r} \bmod P) \bmod Q$，challenge 不带 R

#### get_flag

```c
if ( strcmp(s1, "role=admin;uid=0")
  || (unsigned __int64)(v27 - 1) > 0xCA1F2642806C6F5DLL  // R ∈ [2, P-1]
  || v28 > 0x650F9321403637AELL                            // s ∈ [0, Q-1]
  || !(unsigned int)sub_1C00(s1, v27, v28) )
    v24 = "no";
else
    puts(::s);   // flag
```

msg 必须 strcmp 相等，R 和 s 有范围检查，然后调 verify。

### 解题：

整个签名方案已经逆向清楚了，P 才 64 bit，$G$ 生成的子群阶 $Q \approx 2^{63}$，Pollard's rho 复杂度 $O(\sqrt{Q}) \approx O(2^{31.5})$，多线程几分钟就完事。BSGS 也行但要存 $2^{32}$ 个元素≈32GB 内存，Pollard's rho 只要 O(1) 内存还能并行。

#### solve_Nonce.cpp

解离散对数 $Y = G^X \bmod P$，参数全从逆向结果来：

```cpp
P = 14564401787003760479ULL;  // 0xCA1F2642806C6F5F，case 1 的硬编码
Q = 7282200893501880239ULL;   // 0x650F9321403637AF，case 1 的硬编码
G = 4;                         // case 1 里 4LL
Y = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 4871897555783532952ULL;
                               // 默认值是跑选1拿到的Y，也支持命令行传
```

基础算术，C++ 没有 128 位内建运算所以自己造：

```cpp
inline uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)((__uint128_t)a * b % m);   // 对应 IDA 里 sub_1EB0 的 Barrett reduction
}
inline uint64_t add_mod(uint64_t a, uint64_t b, uint64_t m) {
    uint64_t r = a + b; return r >= m ? r - m : r;
}
inline uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t m) {
    return a >= b ? a - b : a + m - b;
}
inline uint64_t pow_mod(uint64_t a, uint64_t e, uint64_t m) {
    uint64_t r = 1;
    for (; e; e >>= 1, a = mul_mod(a, a, m))
        if (e & 1) r = mul_mod(r, a, m);
    return r;
}
inline uint64_t inv_mod(uint64_t a, uint64_t m) {
    __int128 t = 0, nt = 1, r = m, nr = a;
    while (nr) { /* 扩展欧几里得 */ }
    return r > 1 ? 0 : (uint64_t)(t < 0 ? t + m : t);
}
```

Pollard's rho + Distinguished Points：在群里随机游走，维护 $x = G^a \cdot Y^b$。两条路径碰到同一个 $x$ 时，$G^{a_1} Y^{b_1} = G^{a_2} Y^{b_2}$，所以 $X = (a_1 - a_2)(b_2 - b_1)^{-1} \bmod Q$。

预计算 256 个步进乘数，每个 $m_i = G^{da_i} \cdot Y^{db_i} \bmod P$：

```cpp
steps.reserve(256);
for (int i = 0; i < 256; ++i) {
    uint64_t da = splitmix64(0xD10B5EEDULL + i) % Q;
    uint64_t db = splitmix64(0xBAD5EEDULL + i) % Q;
    steps.push_back({mul_mod(pow_mod(G, da, P), pow_mod(Y, db, P), P), da, db});
}
```

游走时 `splitmix64(x) & 0xFF` 选桶号，$x \leftarrow x \cdot m_i \bmod P$，指数 $a \leftarrow a + da_i$，$b \leftarrow b + db_i$。Distinguished Points 只存低 22 位全 0 的点，减少 hashmap 和锁争用。

编译运行：

```bash
g++ -O2 -pthread -o solve_Nonce solve_Nonce.cpp
./solve_Nonce
# 493944729750866822
```

验一下：

```python
assert pow(4, 493944729750866822, 14564401787003760479) == 4871897555783532952
```

#### solveNounce.py

有了 X，伪造签名。challenge 函数从 verify 伪代码还原：

```c
// sub_1C00 里的 challenge 计算：
v5 = 0x85E77CD426DB34A2LL;       // FNV-1a 初始值
// 逐字节 hash R（8字节，小端序）→ v5
v9 = v5 ^ 0x14650FB0739D0383LL;  // XOR FNV_OFFSET
// 逐字节 hash msg → v9
v12 = v9 % Q;                     // mod Q 得 e
```

转成 Python：

```python
FNV_PRIME  = 0x100000001B3      # 伪代码里反复出现的乘数
FNV_OFFSET = 0x14650FB0739D0383 # XOR 那个常数
R_BASIS    = 0x85E77CD426DB34A2 # hash R 时的初始值

def fnv1a(h, data):
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & ((1 << 64) - 1)  # 对应 C 里 uint64 自然溢出
    return h

def challenge(R, msg):
    h = fnv1a(R_BASIS, R.to_bytes(8, "little")) ^ FNV_OFFSET  # R.to_bytes 对应 v25=a2 逐字节读
    return fnv1a(h, msg) % Q
```

伪造签名，照 sign 函数流程走，绕过黑名单，k 自己取 1：

```python
def forge(msg):
    k = 1                                    # sign里k是确定性派生的，伪造时自己选
    R = pow(G, k, P)                         # 对应 sign 步骤②：R = G^k mod P
    e = challenge(R, msg)                    # 对应 sign 步骤③
    s = (k + X * e) % Q                      # 对应 sign 步骤④：s = k + Xe mod Q
    return R, s
```

$G^s = G^{k+Xe} = G^k \cdot G^{Xe} = R \cdot Y^e \pmod{P}$，verify 只看这个等式成不成立，不管 k 怎么来的，所以 k=1 也能过。

交互：

```python
msg = b"role=admin;uid=0"
R, s = forge(msg)
sock = socket.create_connection((HOST, PORT))
for line in ("4", msg.decode(), str(R), str(s)):
    sock.sendall(line.encode() + b"\n")
```

```
AUVCTF{617542b067bb41f90ece28fbd3c7649751fe5149dd0ed1a8837d67bd13ac5cb5}
```



### exp：

```cpp
// solve_Nonce.cpp
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

struct Point { uint64_t a, b, start; };
struct Step  { uint64_t mul, da, db; };

static uint64_t P, Q, G, Y;
static std::vector<Step> steps;
static std::unordered_map<uint64_t, Point> seen;
static std::mutex mtx;
static std::atomic<bool> done{false};
static std::atomic<uint64_t> answer{0};

inline uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

inline uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m) { return (uint64_t)((__uint128_t)a * b % m); }
inline uint64_t add_mod(uint64_t a, uint64_t b, uint64_t m) { uint64_t r = a + b; return r >= m ? r - m : r; }
inline uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t m) { return a >= b ? a - b : a + m - b; }

inline uint64_t pow_mod(uint64_t a, uint64_t e, uint64_t m) {
    uint64_t r = 1;
    for (; e; e >>= 1, a = mul_mod(a, a, m))
        if (e & 1) r = mul_mod(r, a, m);
    return r;
}

inline uint64_t inv_mod(uint64_t a, uint64_t m) {
    __int128 t = 0, nt = 1, r = m, nr = a;
    while (nr) {
        uint64_t q = (uint64_t)(r / nr);
        __int128 tmp_t = t; t = nt; nt = tmp_t - (__int128)q * nt;
        __int128 tmp_r = r; r = nr; nr = tmp_r - (__int128)q * nr;
    }
    return r > 1 ? 0 : (uint64_t)(t < 0 ? t + m : t);
}

static void worker(int tid, int dp_bits, uint64_t seed) {
    uint64_t mask = (1ULL << dp_bits) - 1;
    uint64_t rng = seed ^ splitmix64(tid);
    while (!done) {
        uint64_t a = (rng = splitmix64(rng)) % Q;
        uint64_t b = (rng = splitmix64(rng)) % Q;
        uint64_t start = splitmix64(a ^ (b << 1) ^ ((uint64_t)tid << 48));
        uint64_t x = mul_mod(pow_mod(G, a, P), pow_mod(Y, b, P), P);

        while (!done) {
            const Step &st = steps[splitmix64(x) & (steps.size() - 1)];
            x = mul_mod(x, st.mul, P);
            a = add_mod(a, st.da, Q);
            b = add_mod(b, st.db, Q);

            if ((splitmix64(x ^ 0xa0761d6478bd642fULL) & mask) != 0) continue;

            std::lock_guard<std::mutex> lock(mtx);
            auto it = seen.find(x);
            if (it == seen.end()) {
                seen.emplace(x, Point{a, b, start});
            } else if (it->second.start != start) {
                uint64_t num = sub_mod(it->second.a, a, Q);
                uint64_t den = sub_mod(b, it->second.b, Q);
                if (den) {
                    uint64_t cand = mul_mod(num, inv_mod(den, Q), Q);
                    if (pow_mod(G, cand, P) == Y) {
                        answer.store(cand);
                        done.store(true);
                        return;
                    }
                }
                seen[x] = Point{a, b, start};
            }
            break;
        }
    }
}

int main(int argc, char **argv) {
    P = 14564401787003760479ULL;
    Q = 7282200893501880239ULL;
    G = 4;
    Y = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 4871897555783532952ULL;

    int threads = argc > 2 ? std::atoi(argv[2]) : (int)std::thread::hardware_concurrency();
    int dp_bits = argc > 3 ? std::atoi(argv[3]) : 22;
    if (threads <= 0) threads = 1;
    if (dp_bits < 8 || dp_bits > 30) dp_bits = 22;

    steps.reserve(256);
    for (int i = 0; i < 256; ++i) {
        uint64_t da = splitmix64(0xD10B5EEDULL + i) % Q;
        uint64_t db = splitmix64(0xBAD5EEDULL + i) % Q;
        steps.push_back({mul_mod(pow_mod(G, da, P), pow_mod(Y, db, P), P), da, db});
    }

    seen.reserve(1 << 20);
    uint64_t seed = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int i = 0; i < threads; ++i)
        pool.emplace_back(worker, i, dp_bits, seed);

    for (auto &t : pool) t.join();
    std::printf("%" PRIu64 "\n", answer.load());
    return 0;
}
```

```python
# solveNounce.py
import socket, time

HOST = "chal.cauc-csa.org.cn"
PORT = XXXXX

P = 0xCA1F2642806C6F5F
Q = 0x650F9321403637AF
G = 4
Y = 4871897555783532952
X = 493944729750866822  # Pollard rho 跑出来的

FNV_PRIME = 0x100000001B3
FNV_MASK = (1 << 64) - 1
FNV_OFFSET = 0x14650FB0739D0383
R_BASIS = 0x85E77CD426DB34A2

def fnv1a(h, data):
    for b in data:
        h = (FNV_PRIME * (h ^ b)) & FNV_MASK
    return h

def challenge(R, msg):
    h = fnv1a(R_BASIS, R.to_bytes(8, "little")) ^ FNV_OFFSET
    return fnv1a(h, msg) % Q

def forge(msg):
    k = 1
    R = pow(G, k, P)
    e = challenge(R, msg)
    s = (k + X * e) % Q
    assert pow(G, X, P) == Y
    assert pow(G, s, P) == (R * pow(Y, e, P)) % P
    return R, s

def recv_some(sock):
    time.sleep(0.15)
    out = b""
    sock.setblocking(False)
    while True:
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            break
        if not chunk:
            break
        out += chunk
    sock.setblocking(True)
    return out.decode("latin1", errors="replace")

def main():
    msg = b"role=admin;uid=0"
    R, s = forge(msg)
    sock = socket.create_connection((HOST, PORT), timeout=5)
    recv_some(sock)
    for line in ("4", msg.decode(), str(R), str(s)):
        sock.sendall(line.encode() + b"\n")
        out = recv_some(sock)
    print(out.strip())
    sock.close()

if __name__ == "__main__":
    main()
```
