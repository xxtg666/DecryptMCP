from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish, ChaCha20, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA1, SHA384, SHA512, MD5
from Crypto.Signature import pss, pkcs1_15


def register(mcp):

    @mcp.tool()
    def aes_encrypt(plaintext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "", nonce_hex: str = "") -> str:
        """AES加密。plaintext_hex/key_hex/iv_hex为hex字符串。mode: ECB/CBC/CTR/GCM/OFB/CFB。返回hex密文(GCM模式额外返回tag)"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                ct = cipher.encrypt(pad(pt, 16))
                return ct.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(pt, 16))
                return f"iv={iv.hex()} ct={ct.hex()}"
            elif mode == "CTR":
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 8
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                ct = cipher.encrypt(pt)
                return f"nonce={nonce.hex()} ct={ct.hex()}"
            elif mode == "GCM":
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 12
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ct, tag = cipher.encrypt_and_digest(pt)
                return f"nonce={nonce.hex()} ct={ct.hex()} tag={tag.hex()}"
            elif mode == "OFB":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_OFB, iv=iv)
                ct = cipher.encrypt(pt)
                return f"iv={iv.hex()} ct={ct.hex()}"
            elif mode == "CFB":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                ct = cipher.encrypt(pt)
                return f"iv={iv.hex()} ct={ct.hex()}"
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def aes_decrypt(ciphertext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "", nonce_hex: str = "", tag_hex: str = "") -> str:
        """AES解密。ciphertext_hex/key_hex/iv_hex为hex字符串。mode: ECB/CBC/CTR/GCM/OFB/CFB。返回hex明文"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                pt = unpad(cipher.decrypt(ct), 16)
                return pt.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(ct), 16)
                return pt.hex()
            elif mode == "CTR":
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 8
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                pt = cipher.decrypt(ct)
                return pt.hex()
            elif mode == "GCM":
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 12
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if tag_hex:
                    pt = cipher.decrypt_and_verify(ct, bytes.fromhex(tag_hex))
                else:
                    pt = cipher.decrypt(ct)
                return pt.hex()
            elif mode == "OFB":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_OFB, iv=iv)
                pt = cipher.decrypt(ct)
                return pt.hex()
            elif mode == "CFB":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 16
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                pt = cipher.decrypt(ct)
                return pt.hex()
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def des_encrypt(plaintext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """DES加密。key为8字节hex。mode: ECB/CBC"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = DES.new(key, DES.MODE_ECB)
                ct = cipher.encrypt(pad(pt, 8))
                return ct.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(pt, 8))
                return f"iv={iv.hex()} ct={ct.hex()}"
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def des_decrypt(ciphertext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """DES解密。key为8字节hex。mode: ECB/CBC"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = DES.new(key, DES.MODE_ECB)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def triple_des_encrypt(plaintext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """3DES加密。key为16或24字节hex。mode: ECB/CBC"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = DES3.new(key, DES3.MODE_ECB)
                ct = cipher.encrypt(pad(pt, 8))
                return ct.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(pt, 8))
                return f"iv={iv.hex()} ct={ct.hex()}"
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def triple_des_decrypt(ciphertext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """3DES解密。key为16或24字节hex。mode: ECB/CBC"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = DES3.new(key, DES3.MODE_ECB)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rc4_cipher(data_hex: str, key_hex: str) -> str:
        """RC4流密码加解密(对称)。data和key为hex字符串"""
        try:
            data = bytes.fromhex(data_hex)
            key = bytes.fromhex(key_hex)
            cipher = ARC4.new(key)
            return cipher.encrypt(data).hex()
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def blowfish_encrypt(plaintext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """Blowfish加密。key为4-56字节hex。mode: ECB/CBC"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = Blowfish.new(key, Blowfish.MODE_ECB)
                ct = cipher.encrypt(pad(pt, 8))
                return ct.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(pt, 8))
                return f"iv={iv.hex()} ct={ct.hex()}"
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def blowfish_decrypt(ciphertext_hex: str, key_hex: str, mode: str = "ECB", iv_hex: str = "") -> str:
        """Blowfish解密。key为4-56字节hex。mode: ECB/CBC"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(key_hex)
            if mode == "ECB":
                cipher = Blowfish.new(key, Blowfish.MODE_ECB)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            elif mode == "CBC":
                iv = bytes.fromhex(iv_hex) if iv_hex else b'\x00' * 8
                cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(ct), 8)
                return pt.hex()
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def chacha20_encrypt(plaintext_hex: str, key_hex: str, nonce_hex: str = "") -> str:
        """ChaCha20加密。key为32字节hex，nonce为8或12字节hex"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 8
            cipher = ChaCha20.new(key=key, nonce=nonce)
            ct = cipher.encrypt(pt)
            return f"nonce={nonce.hex()} ct={ct.hex()}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def chacha20_decrypt(ciphertext_hex: str, key_hex: str, nonce_hex: str = "") -> str:
        """ChaCha20解密。key为32字节hex，nonce为8或12字节hex"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex) if nonce_hex else b'\x00' * 8
            cipher = ChaCha20.new(key=key, nonce=nonce)
            pt = cipher.decrypt(ct)
            return pt.hex()
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_generate_keys(bits: int = 2048) -> str:
        """RSA密钥对生成。返回PEM格式的公钥和私钥"""
        try:
            key = RSA.generate(bits)
            private_pem = key.export_key().decode()
            public_pem = key.publickey().export_key().decode()
            return f"=== Private Key ===\n{private_pem}\n\n=== Public Key ===\n{public_pem}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_encrypt(plaintext_hex: str, public_key_pem: str, padding: str = "OAEP") -> str:
        """RSA加密。plaintext_hex为hex字符串，public_key_pem为PEM格式公钥。padding: OAEP/PKCS1_v1_5"""
        try:
            pt = bytes.fromhex(plaintext_hex)
            key = RSA.import_key(public_key_pem)
            if padding == "PKCS1_v1_5":
                cipher = PKCS1_v1_5.new(key)
            else:
                cipher = PKCS1_OAEP.new(key)
            ct = cipher.encrypt(pt)
            return ct.hex()
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_decrypt(ciphertext_hex: str, private_key_pem: str, padding: str = "OAEP") -> str:
        """RSA解密。ciphertext_hex为hex字符串，private_key_pem为PEM格式私钥。padding: OAEP/PKCS1_v1_5"""
        try:
            ct = bytes.fromhex(ciphertext_hex)
            key = RSA.import_key(private_key_pem)
            if padding == "PKCS1_v1_5":
                cipher = PKCS1_v1_5.new(key)
                pt = cipher.decrypt(ct, sentinel=None)
            else:
                cipher = PKCS1_OAEP.new(key)
                pt = cipher.decrypt(ct)
            if pt is None:
                return "错误: 解密失败(填充验证不通过)"
            return pt.hex()
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_sign(data_hex: str, private_key_pem: str, algorithm: str = "SHA256", scheme: str = "PKCS1_v1_5") -> str:
        """RSA签名。data_hex为hex字符串，scheme: PKCS1_v1_5/PSS。algorithm: SHA256/SHA1/SHA384/SHA512/MD5"""
        try:
            hash_map = {"SHA256": SHA256, "SHA1": SHA1, "SHA384": SHA384, "SHA512": SHA512, "MD5": MD5}
            if algorithm not in hash_map:
                return f"错误: 不支持的算法 {algorithm}，可用: {', '.join(hash_map.keys())}"
            data = bytes.fromhex(data_hex)
            key = RSA.import_key(private_key_pem)
            h = hash_map[algorithm].new(data)
            if scheme == "PSS":
                signature = pss.new(key).sign(h)
            else:
                signature = pkcs1_15.new(key).sign(h)
            return f"签名 (hex): {signature.hex()}\n算法: {algorithm}\n方案: {scheme}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_verify(data_hex: str, signature_hex: str, public_key_pem: str, algorithm: str = "SHA256", scheme: str = "PKCS1_v1_5") -> str:
        """RSA验签。data_hex和signature_hex为hex字符串。scheme: PKCS1_v1_5/PSS"""
        try:
            hash_map = {"SHA256": SHA256, "SHA1": SHA1, "SHA384": SHA384, "SHA512": SHA512, "MD5": MD5}
            if algorithm not in hash_map:
                return f"错误: 不支持的算法 {algorithm}"
            data = bytes.fromhex(data_hex)
            sig = bytes.fromhex(signature_hex)
            key = RSA.import_key(public_key_pem)
            h = hash_map[algorithm].new(data)
            try:
                if scheme == "PSS":
                    pss.new(key).verify(h, sig)
                else:
                    pkcs1_15.new(key).verify(h, sig)
                return "验签结果: 签名有效 ✓"
            except (ValueError, TypeError):
                return "验签结果: 签名无效 ✗"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_raw(message: str, n: str, key: str) -> str:
        """RSA原始数学运算(Textbook RSA)。计算 message^key mod n。参数均为十进制整数字符串。可用于CTF中直接操作RSA"""
        try:
            m = int(message)
            n_val = int(n)
            k = int(key)
            result = pow(m, k, n_val)
            result_hex = hex(result)[2:]
            if len(result_hex) % 2:
                result_hex = '0' + result_hex
            try:
                text = bytes.fromhex(result_hex).decode('utf-8', errors='replace')
            except Exception:
                text = ""
            lines = [f"结果 (十进制): {result}", f"结果 (hex): {result_hex}"]
            if text and all(32 <= ord(c) < 127 for c in text):
                lines.append(f"结果 (文本): {text}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"
