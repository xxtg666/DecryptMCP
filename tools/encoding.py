import base64
import urllib.parse
import html
import codecs
import binascii
import quopri
import zlib
import gzip
import bz2
import lzma
import io


def register(mcp):

    @mcp.tool()
    def base16_encode_decode(data: str, mode: str = "encode") -> str:
        """Base16(hex)编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return base64.b16encode(data.encode('utf-8')).decode('ascii')
            else:
                return base64.b16decode(data.strip(), casefold=True).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def base32_encode_decode(data: str, mode: str = "encode") -> str:
        """Base32编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return base64.b32encode(data.encode('utf-8')).decode('ascii')
            else:
                padding = (8 - len(data.strip()) % 8) % 8
                return base64.b32decode(data.strip() + '=' * padding).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def base58_encode_decode(data: str, mode: str = "encode") -> str:
        """Base58编解码(Bitcoin字母表)。mode: encode/decode"""
        try:
            ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            if mode == "encode":
                raw = data.encode('utf-8')
                n = int.from_bytes(raw, 'big')
                result = []
                while n > 0:
                    n, r = divmod(n, 58)
                    result.append(ALPHABET[r:r+1])
                for b in raw:
                    if b == 0:
                        result.append(ALPHABET[0:1])
                    else:
                        break
                return b''.join(reversed(result)).decode('ascii')
            else:
                n = 0
                for ch in data.strip().encode('ascii'):
                    n = n * 58 + ALPHABET.index(ch)
                leading_zeros = 0
                for ch in data.strip().encode('ascii'):
                    if ch == ALPHABET[0]:
                        leading_zeros += 1
                    else:
                        break
                result = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
                result = b'\x00' * leading_zeros + result
                return result.decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def base64_encode_decode(data: str, mode: str = "encode", variant: str = "standard") -> str:
        """Base64编解码。mode: encode/decode。variant: standard/urlsafe"""
        try:
            if mode == "encode":
                raw = data.encode('utf-8')
                if variant == "urlsafe":
                    return base64.urlsafe_b64encode(raw).decode('ascii')
                return base64.b64encode(raw).decode('ascii')
            else:
                s = data.strip()
                padding = (4 - len(s) % 4) % 4
                s += '=' * padding
                if variant == "urlsafe":
                    return base64.urlsafe_b64decode(s).decode('utf-8', errors='replace')
                return base64.b64decode(s).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def base85_encode_decode(data: str, mode: str = "encode") -> str:
        """Base85编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return base64.b85encode(data.encode('utf-8')).decode('ascii')
            else:
                return base64.b85decode(data.strip()).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def url_encode_decode(data: str, mode: str = "encode") -> str:
        """URL编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return urllib.parse.quote(data, safe='')
            else:
                return urllib.parse.unquote(data)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def html_entity_encode_decode(data: str, mode: str = "encode") -> str:
        """HTML实体编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return html.escape(data, quote=True)
            else:
                return html.unescape(data)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hex_encode_decode(data: str, mode: str = "encode") -> str:
        """十六进制文本编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return data.encode('utf-8').hex()
            else:
                clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
                return bytes.fromhex(clean).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def binary_encode_decode(data: str, mode: str = "encode") -> str:
        """二进制文本编解码。mode: encode(文本->8位二进制)/decode(二进制->文本)"""
        try:
            if mode == "encode":
                return " ".join(format(b, '08b') for b in data.encode('utf-8'))
            else:
                bits = data.replace(" ", "")
                chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
                return bytes(int(b, 2) for b in chars if len(b) == 8).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def octal_encode_decode(data: str, mode: str = "encode") -> str:
        """八进制文本编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return " ".join(format(b, '03o') for b in data.encode('utf-8'))
            else:
                parts = data.strip().split()
                return bytes(int(p, 8) for p in parts).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def decimal_encode_decode(data: str, mode: str = "encode") -> str:
        """十进制ASCII编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return " ".join(str(b) for b in data.encode('utf-8'))
            else:
                parts = data.strip().split()
                return bytes(int(p) for p in parts).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def morse_code(data: str, mode: str = "encode") -> str:
        """摩尔斯电码编解码。mode: encode/decode。用/分隔单词"""
        try:
            MORSE = {
                'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
                'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
                'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
                'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
                'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
                'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
                '3': '...--', '4': '....-', '5': '.....', '6': '-....',
                '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-',
                ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
                '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
                ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
                '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-',
                '@': '.--.-.', ' ': '/'
            }
            if mode == "encode":
                result = []
                for ch in data.upper():
                    if ch in MORSE:
                        result.append(MORSE[ch])
                    else:
                        result.append(ch)
                return " ".join(result)
            else:
                REV = {v: k for k, v in MORSE.items()}
                words = data.strip().split(" / ")
                result = []
                for word in words:
                    letters = word.strip().split()
                    decoded = []
                    for code in letters:
                        code = code.strip()
                        if code in REV:
                            decoded.append(REV[code])
                        elif code == '/':
                            decoded.append(' ')
                        else:
                            decoded.append(f'[{code}]')
                    result.append("".join(decoded))
                return " ".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def uuencode_decode(data: str, mode: str = "encode") -> str:
        """UUencode编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                encoded = binascii.b2a_uu(data.encode('utf-8'))
                return encoded.decode('ascii')
            else:
                return binascii.a2b_uu(data).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def quoted_printable(data: str, mode: str = "encode") -> str:
        """Quoted-Printable编解码。mode: encode/decode"""
        try:
            if mode == "encode":
                return quopri.encodestring(data.encode('utf-8')).decode('ascii')
            else:
                return quopri.decodestring(data.encode('ascii')).decode('utf-8', errors='replace')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def punycode_encode_decode(data: str, mode: str = "encode") -> str:
        """Punycode编解码(国际化域名)。mode: encode/decode"""
        try:
            if mode == "encode":
                return data.encode('idna').decode('ascii')
            else:
                return data.encode('ascii').decode('idna')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def unicode_escape(data: str, mode: str = "encode") -> str:
        r"""Unicode转义序列编解码。mode: encode(文本->\uXXXX)/decode(\uXXXX->文本)"""
        try:
            if mode == "encode":
                return data.encode('unicode_escape').decode('ascii')
            else:
                return data.encode('ascii').decode('unicode_escape')
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def compress_decompress(data: str, algorithm: str = "zlib", mode: str = "decompress", input_format: str = "hex") -> str:
        """压缩/解压缩。algorithm: zlib/gzip/bz2/lzma/auto。mode: compress/decompress。input_format: text/hex/base64"""
        try:
            if mode == "compress":
                if input_format == "hex":
                    raw = bytes.fromhex(data.replace(" ", ""))
                else:
                    raw = data.encode('utf-8')

                if algorithm == "zlib":
                    result = zlib.compress(raw)
                elif algorithm == "gzip":
                    buf = io.BytesIO()
                    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                        f.write(raw)
                    result = buf.getvalue()
                elif algorithm == "bz2":
                    result = bz2.compress(raw)
                elif algorithm == "lzma":
                    result = lzma.compress(raw)
                else:
                    return f"错误: 不支持的算法 {algorithm}。可用: zlib/gzip/bz2/lzma"

                return (f"压缩结果 (hex): {result.hex()}\n"
                        f"压缩结果 (base64): {base64.b64encode(result).decode()}\n"
                        f"原始大小: {len(raw)} 字节\n"
                        f"压缩大小: {len(result)} 字节")
            else:
                if input_format == "hex":
                    raw = bytes.fromhex(data.replace(" ", ""))
                elif input_format == "base64":
                    raw = base64.b64decode(data)
                else:
                    raw = data.encode('latin-1')

                if algorithm == "auto":
                    for name, func in [("zlib", zlib.decompress), ("gzip", gzip.decompress),
                                       ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
                        try:
                            result = func(raw)
                            algorithm = name
                            break
                        except Exception:
                            continue
                    else:
                        return "错误: 无法自动识别压缩算法"
                elif algorithm == "zlib":
                    result = zlib.decompress(raw)
                elif algorithm == "gzip":
                    result = gzip.decompress(raw)
                elif algorithm == "bz2":
                    result = bz2.decompress(raw)
                elif algorithm == "lzma":
                    result = lzma.decompress(raw)
                else:
                    return f"错误: 不支持的算法 {algorithm}"

                try:
                    text = result.decode('utf-8')
                    return (f"解压结果 ({algorithm}):\n{text}\n\n"
                            f"压缩大小: {len(raw)} 字节\n解压大小: {len(result)} 字节")
                except UnicodeDecodeError:
                    return (f"解压结果 (hex): {result.hex()}\n"
                            f"压缩大小: {len(raw)} 字节\n解压大小: {len(result)} 字节")
        except Exception as e:
            return f"错误: {e}"
