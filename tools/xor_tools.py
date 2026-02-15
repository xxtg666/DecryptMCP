def register(mcp):

    @mcp.tool()
    def xor_encrypt_decrypt(data_hex: str, key_hex: str) -> str:
        """XOR加解密(对称)。data和key为hex字符串"""
        try:
            data = bytes.fromhex(data_hex)
            key = bytes.fromhex(key_hex)
            result = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
            return result.hex()
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def xor_single_byte_bruteforce(data_hex: str) -> str:
        """单字节XOR暴力破解。显示所有256种结果(仅显示可打印结果)"""
        try:
            data = bytes.fromhex(data_hex)
            lines = []
            for key in range(256):
                result = bytes(d ^ key for d in data)
                try:
                    text = result.decode('ascii')
                    if all(32 <= c < 127 or c in (9, 10, 13) for c in result):
                        lines.append(f"Key 0x{key:02x} ({key:3d}): {text}")
                except UnicodeDecodeError:
                    pass
            if not lines:
                lines.append("没有找到完全可打印的结果")
                for key in range(256):
                    result = bytes(d ^ key for d in data)
                    text = result.decode('latin-1')
                    lines.append(f"Key 0x{key:02x}: {text}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def xor_repeating_key(data_hex: str, key_hex: str) -> str:
        """重复密钥XOR加解密。data和key为hex字符串"""
        try:
            data = bytes.fromhex(data_hex)
            key = bytes.fromhex(key_hex)
            result = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
            hex_result = result.hex()
            try:
                text = result.decode('utf-8')
                return f"Hex: {hex_result}\nText: {text}"
            except UnicodeDecodeError:
                return f"Hex: {hex_result}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def xor_known_plaintext(ciphertext_hex: str, known_plaintext: str) -> str:
        """已知明文攻击推导XOR密钥。ciphertext_hex为hex，known_plaintext为明文"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            pt = known_plaintext.encode('utf-8')
            min_len = min(len(ct), len(pt))
            key = bytes(ct[i] ^ pt[i] for i in range(min_len))
            return f"推导出的密钥 (hex): {key.hex()}\n密钥 (text): {key.decode('latin-1')}\n密钥长度: {min_len} 字节"
        except Exception as e:
            return f"错误: {e}"
