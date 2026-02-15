# DecryptMCP

一套为 AI 打造的密码学 MCP 工具集，涵盖 117 个工具，覆盖编码、古典密码、现代加密、哈希、RSA 攻击、椭圆曲线、格基规约等，让 AI 能够独立解决加密谜题和 CTF 密码学挑战。

> 由 Claude Opus 4.6 独立编写。

## 功能概览

| 分类 | 工具数 | 说明 |
|------|--------|------|
| 古典密码 | 20 | Caesar、Vigenère（含自动破解）、Playfair、Hill、仿射、栅栏、培根等 |
| 现代加密 | 18 | AES (6种模式)、DES、3DES、RC4、Blowfish、ChaCha20、RSA (OAEP/PKCS1_v1_5/签名/验签/原始运算) |
| RSA 攻击 | 7 | Wiener、Fermat 分解、共模攻击、Hastad 广播、Pollard p-1/rho、小指数攻击 |
| 椭圆曲线 | 5 | 点加法、标量乘法、查找曲线点、点阶计算、ECDLP |
| 哈希 | 8 | MD5/SHA 全系列、HMAC、bcrypt（哈希+验证）、CRC32、PBKDF2、哈希识别、字典破解 |
| 编码 | 18 | Base16/32/58/64/85、URL、HTML、Hex、二进制、八进制、摩尔斯、Punycode、zlib/gzip/bz2/lzma 压缩解压等 |
| XOR | 4 | XOR 加解密、单字节暴力破解、重复密钥、已知明文攻击 |
| 矩阵/格 | 7 | 矩阵运算 mod p、矩阵求逆、行列式、线性方程组、Hill 密码、LLL 格基规约、Berlekamp-Massey |
| 数论 | 12 | 素因数分解、素性测试、模逆/模幂、欧拉函数、CRT、扩展 GCD、离散对数、模开方、进制转换 |
| 字符串分析 | 6 | 频率分析、信息熵、模式检测、hex dump、字符信息、字符串变换 |
| 趣味/隐写 | 6 | Brainfuck、Ook!、NATO 音标、Pig Latin、零宽字符隐写 |
| 网络/杂项 | 6 | 网络搜索、HTTP 请求、DNS 查询、JWT 解码、文件魔数识别、时间戳转换等 |

## 安装

```bash
git clone https://github.com/xxtg666/DecryptMCP
cd DecryptMCP
pip install -r requirements.txt
```

### 依赖

- Python 3.10+
- `mcp[cli]` — MCP 协议框架
- `pycryptodome` — 现代加密算法
- `sympy` — 数论与数学运算
- `httpx` — HTTP 客户端
- `bcrypt` — bcrypt 哈希

## 配置

### Claude Desktop

在 `claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "DecryptMCP": {
      "command": "python",
      "args": ["path/to/DecryptMCP/server.py"],
      "env": {}
    }
  }
}
```

### Claude Code

在 `.mcp.json` 中添加：

```json
{
  "mcpServers": {
    "DecryptMCP": {
      "command": "python",
      "args": ["path/to/DecryptMCP/server.py"]
    }
  }
}
```

### 其他 MCP 客户端

DecryptMCP 遵循 MCP 标准协议，兼容任何支持 MCP 的客户端。

## AI 提示词

项目包含 [`PROMPT.md`](PROMPT.md)，提供了一套完整的 AI 解密工作提示词，指导 AI 按照「观察 → 分析 → 假设 → 验证 → 迭代」的方法论使用工具集独立解题。可将其作为 System Prompt 注入对话。

## 工具列表

<details>
<summary>点击展开完整工具列表（117 个）</summary>

### 古典密码
| 工具 | 说明 |
|------|------|
| `caesar_cipher` | 凯撒密码加解密 |
| `caesar_bruteforce` | 凯撒暴力破解 (25 种偏移) |
| `rot13` | ROT13 |
| `rot_n` | ROT-N 任意偏移 |
| `rot47` | ROT47 (ASCII 33-126) |
| `vigenere_cipher` | 维吉尼亚密码加解密 |
| `vigenere_break` | 维吉尼亚自动破解 (IoC + 频率分析) |
| `atbash_cipher` | 埃特巴什密码 |
| `rail_fence_cipher` | 栅栏密码加解密 |
| `rail_fence_bruteforce` | 栅栏密码暴力破解 |
| `affine_cipher` | 仿射密码加解密 |
| `playfair_cipher` | Playfair 密码 |
| `columnar_transposition` | 列置换密码 |
| `bacon_cipher` | 培根密码 |
| `polybius_square` | 波利比奥斯方阵 |
| `beaufort_cipher` | Beaufort 密码 |
| `autokey_cipher` | 自动密钥密码 |
| `keyword_cipher` | 关键字替换密码 |
| `hill_cipher` | Hill 密码 (矩阵加密) |

### 现代加密
| 工具 | 说明 |
|------|------|
| `aes_encrypt` / `aes_decrypt` | AES (ECB/CBC/CTR/GCM/OFB/CFB) |
| `des_encrypt` / `des_decrypt` | DES |
| `triple_des_encrypt` / `triple_des_decrypt` | 3DES |
| `rc4_cipher` | RC4 流密码 |
| `blowfish_encrypt` / `blowfish_decrypt` | Blowfish |
| `chacha20_encrypt` / `chacha20_decrypt` | ChaCha20 |
| `rsa_generate_keys` | RSA 密钥对生成 |
| `rsa_encrypt` / `rsa_decrypt` | RSA 加解密 (OAEP/PKCS1_v1_5) |
| `rsa_sign` / `rsa_verify` | RSA 签名/验签 (PKCS1_v1_5/PSS) |
| `rsa_raw` | Textbook RSA 原始运算 |

### RSA 攻击
| 工具 | 说明 |
|------|------|
| `rsa_wiener_attack` | Wiener 攻击 (小私钥指数) |
| `rsa_fermat_factor` | Fermat 分解 (p, q 接近) |
| `rsa_common_modulus` | 共模攻击 |
| `rsa_hastad_broadcast` | Hastad 广播攻击 |
| `rsa_pollard_p1` | Pollard p-1 分解 |
| `rsa_pollard_rho` | Pollard rho 分解 |
| `rsa_small_e_attack` | 小公钥指数攻击 |

### 椭圆曲线
| 工具 | 说明 |
|------|------|
| `ecc_point_add` | 点加法 |
| `ecc_scalar_mult` | 标量乘法 |
| `ecc_find_points` | 枚举曲线上所有点 |
| `ecc_point_order` | 计算点的阶 |
| `ecc_ecdlp` | ECDLP (Baby-step Giant-step) |

### 哈希
| 工具 | 说明 |
|------|------|
| `hash_compute` | 计算哈希 (MD5/SHA 全系列/SHA3) |
| `hash_identify` | 识别哈希类型 |
| `hash_crack_dictionary` | 字典破解哈希 |
| `hmac_compute` | HMAC 计算 |
| `bcrypt_hash` / `bcrypt_verify` | bcrypt 哈希与验证 |
| `crc32_compute` | CRC32 |
| `pbkdf2_derive` | PBKDF2 密钥派生 |

### 编码
| 工具 | 说明 |
|------|------|
| `base16_encode_decode` | Base16 (Hex) |
| `base32_encode_decode` | Base32 |
| `base58_encode_decode` | Base58 (Bitcoin) |
| `base64_encode_decode` | Base64 / URL-safe Base64 |
| `base85_encode_decode` | Base85 |
| `url_encode_decode` | URL 编码 |
| `html_entity_encode_decode` | HTML 实体 |
| `hex_encode_decode` | 十六进制文本 |
| `binary_encode_decode` | 二进制 |
| `octal_encode_decode` | 八进制 |
| `decimal_encode_decode` | 十进制 ASCII |
| `morse_code` | 摩尔斯电码 |
| `uuencode_decode` | UUencode |
| `quoted_printable` | Quoted-Printable |
| `punycode_encode_decode` | Punycode |
| `unicode_escape` | Unicode 转义 |
| `compress_decompress` | 压缩/解压 (zlib/gzip/bz2/lzma/auto) |

### XOR
| 工具 | 说明 |
|------|------|
| `xor_encrypt_decrypt` | XOR 加解密 |
| `xor_single_byte_bruteforce` | 单字节 XOR 暴力破解 |
| `xor_repeating_key` | 重复密钥 XOR |
| `xor_known_plaintext` | 已知明文攻击推导密钥 |

### 矩阵 / 格
| 工具 | 说明 |
|------|------|
| `matrix_mod_operation` | 矩阵乘法/加法/幂 mod m |
| `matrix_inverse_mod` | 矩阵求逆 mod m |
| `matrix_det_mod` | 行列式 mod m |
| `solve_linear_mod` | 解线性方程组 Ax=b mod m |
| `lll_reduce` | LLL 格基规约 |
| `berlekamp_massey` | Berlekamp-Massey (LFSR 恢复) |

### 数论
| 工具 | 说明 |
|------|------|
| `math_eval` | 安全数学表达式计算 |
| `base_convert` | 任意进制转换 (2-62) |
| `prime_factorize` | 素因数分解 |
| `is_prime` | 素性测试 |
| `gcd_lcm` | GCD / LCM |
| `mod_inverse` | 模逆元 |
| `mod_pow` | 模幂运算 |
| `euler_totient` | 欧拉函数 |
| `chinese_remainder_theorem` | 中国剩余定理 |
| `extended_gcd` | 扩展欧几里得 |
| `discrete_log` | 离散对数 |
| `nth_root_mod` | 模开方 |

### 字符串分析
| 工具 | 说明 |
|------|------|
| `frequency_analysis` | 字符频率分析 |
| `entropy_calculate` | 信息熵 (Shannon) |
| `string_reverse` | 字符串反转 |
| `char_info` | 字符 ASCII/Unicode 信息 |
| `string_transform` | 字符串变换 |
| `pattern_detect` | 编码模式检测 |
| `hex_dump` | 十六进制转储 |

### 趣味 / 隐写
| 工具 | 说明 |
|------|------|
| `brainfuck_execute` / `brainfuck_encode` | Brainfuck |
| `ook_cipher` | Ook! 语言 |
| `nato_phonetic` | NATO 音标字母 |
| `pig_latin` | Pig Latin |
| `zero_width_stego` | 零宽字符隐写 |

### 网络 / 杂项
| 工具 | 说明 |
|------|------|
| `web_search` | 网络搜索 (DuckDuckGo) |
| `http_request` | HTTP 请求 |
| `dns_lookup` | DNS 查询 |
| `jwt_decode` | JWT 令牌解码 |
| `file_magic_identify` | 文件头魔数识别 |
| `timestamp_convert` | Unix 时间戳转换 |
| `uuid_generate` | UUID 生成 |
| `random_generate` | 安全随机数生成 |
| `regex_test` | 正则表达式测试 |

</details>

## 许可证

MIT License
