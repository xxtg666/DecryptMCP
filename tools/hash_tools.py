import hashlib
import hmac as hmac_mod
import binascii
import bcrypt
import secrets

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256 as C_SHA256, SHA1 as C_SHA1, SHA512 as C_SHA512, HMAC as C_HMAC


def register(mcp):

    @mcp.tool()
    def hash_compute(data: str, algorithm: str = "all", input_format: str = "text") -> str:
        """计算哈希值。algorithm: md5/sha1/sha256/sha384/sha512/sha3_256/sha3_512/all。input_format: text/hex"""
        try:
            if input_format == "hex":
                raw = bytes.fromhex(data)
            else:
                raw = data.encode('utf-8')
            algos = {
                "md5": hashlib.md5,
                "sha1": hashlib.sha1,
                "sha256": hashlib.sha256,
                "sha384": hashlib.sha384,
                "sha512": hashlib.sha512,
                "sha3_256": hashlib.sha3_256,
                "sha3_512": hashlib.sha3_512,
            }
            if algorithm == "all":
                lines = []
                for name, func in algos.items():
                    lines.append(f"{name:10s}: {func(raw).hexdigest()}")
                return "\n".join(lines)
            elif algorithm in algos:
                return f"{algorithm}: {algos[algorithm](raw).hexdigest()}"
            else:
                return f"错误: 不支持的算法 {algorithm}，可用: {', '.join(algos.keys())}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hash_identify(hash_value: str) -> str:
        """根据哈希长度和格式识别可能的哈希类型"""
        try:
            h = hash_value.strip()
            length = len(h)
            candidates = []
            hex_chars = all(c in '0123456789abcdefABCDEF' for c in h)
            if h.startswith("$2") and "$" in h[2:]:
                candidates.append("bcrypt")
            if h.startswith("$6$"):
                candidates.append("SHA-512 (Unix crypt)")
            if h.startswith("$5$"):
                candidates.append("SHA-256 (Unix crypt)")
            if h.startswith("$1$"):
                candidates.append("MD5 (Unix crypt)")
            if hex_chars:
                mapping = {
                    8: ["CRC32"],
                    32: ["MD5", "NTLM", "MD4"],
                    40: ["SHA-1", "MySQL5"],
                    56: ["SHA-224", "SHA3-224"],
                    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
                    96: ["SHA-384", "SHA3-384"],
                    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
                }
                if length in mapping:
                    candidates.extend(mapping[length])
            if not candidates:
                candidates.append(f"未知 (长度={length}, hex={hex_chars})")
            return f"哈希: {h}\n长度: {length}\n可能的类型: {', '.join(candidates)}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hmac_compute(data: str, key: str, algorithm: str = "sha256", input_format: str = "text") -> str:
        """计算HMAC。algorithm: md5/sha1/sha256/sha512。input_format: text/hex"""
        try:
            if input_format == "hex":
                raw = bytes.fromhex(data)
                key_bytes = bytes.fromhex(key)
            else:
                raw = data.encode('utf-8')
                key_bytes = key.encode('utf-8')
            algo_map = {
                "md5": hashlib.md5,
                "sha1": hashlib.sha1,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512,
            }
            if algorithm not in algo_map:
                return f"错误: 不支持的算法 {algorithm}"
            h = hmac_mod.new(key_bytes, raw, algo_map[algorithm])
            return f"HMAC-{algorithm.upper()}: {h.hexdigest()}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hash_crack_dictionary(hash_value: str, algorithm: str = "md5", wordlist: str = "") -> str:
        """字典攻击破解哈希。wordlist: 换行分隔的字典单词列表"""
        try:
            if not wordlist:
                return "错误: 请提供wordlist参数(换行分隔的字典单词)"
            algo_map = {
                "md5": hashlib.md5,
                "sha1": hashlib.sha1,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512,
            }
            if algorithm not in algo_map:
                return f"错误: 不支持的算法 {algorithm}"
            hash_func = algo_map[algorithm]
            target = hash_value.strip().lower()
            for word in wordlist.split("\n"):
                word = word.strip()
                if not word:
                    continue
                if hash_func(word.encode('utf-8')).hexdigest() == target:
                    return f"破解成功!\n哈希: {target}\n明文: {word}\n算法: {algorithm}"
            return f"未找到匹配。已尝试 {len(wordlist.split(chr(10)))} 个词。"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def bcrypt_hash(data: str, rounds: int = 12) -> str:
        """bcrypt哈希计算"""
        try:
            hashed = bcrypt.hashpw(data.encode('utf-8'), bcrypt.gensalt(rounds=rounds))
            return f"bcrypt: {hashed.decode('utf-8')}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def crc32_compute(data: str, input_format: str = "text") -> str:
        """计算CRC32。input_format: text/hex"""
        try:
            if input_format == "hex":
                raw = bytes.fromhex(data)
            else:
                raw = data.encode('utf-8')
            crc = binascii.crc32(raw) & 0xffffffff
            return f"CRC32: {crc:08x} (十进制: {crc})"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def pbkdf2_derive(password: str, salt: str = "", iterations: int = 100000, key_length: int = 32, algorithm: str = "sha256", salt_format: str = "text") -> str:
        """PBKDF2密钥派生。从密码派生指定长度的密钥。algorithm: sha256/sha1/sha512。salt_format: text/hex"""
        try:
            hash_map = {"sha256": C_SHA256, "sha1": C_SHA1, "sha512": C_SHA512}
            if algorithm not in hash_map:
                return f"错误: 不支持的算法 {algorithm}，可用: {', '.join(hash_map.keys())}"
            if salt_format == "hex" and salt:
                salt_bytes = bytes.fromhex(salt)
            elif salt:
                salt_bytes = salt.encode('utf-8')
            else:
                salt_bytes = secrets.token_bytes(16)
            hash_module = hash_map[algorithm]
            derived = PBKDF2(password.encode('utf-8'), salt_bytes, dkLen=key_length, count=iterations, prf=lambda p, s: C_HMAC.new(p, s, hash_module).digest())
            return (f"派生密钥 (hex): {derived.hex()}\n"
                    f"Salt (hex): {salt_bytes.hex()}\n"
                    f"迭代次数: {iterations}\n"
                    f"密钥长度: {key_length} 字节\n"
                    f"算法: PBKDF2-HMAC-{algorithm.upper()}")
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def bcrypt_verify(password: str, hash_value: str) -> str:
        """bcrypt哈希验证。验证密码是否与bcrypt哈希匹配"""
        try:
            result = bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8'))
            if result:
                return "验证结果: 密码匹配 ✓"
            else:
                return "验证结果: 密码不匹配 ✗"
        except Exception as e:
            return f"错误: {e}"
