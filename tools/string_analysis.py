import math
import re
import base64
from collections import Counter


def register(mcp):

    @mcp.tool()
    def frequency_analysis(text: str) -> str:
        """字符频率分析。返回各字符出现次数和百分比"""
        try:
            total = len(text)
            if total == 0:
                return "空文本"
            counter = Counter(text.upper())
            lines = [f"总字符数: {total}", ""]

            alpha_only = {k: v for k, v in counter.items() if k.isalpha()}
            alpha_total = sum(alpha_only.values())
            if alpha_only:
                lines.append("字母频率:")
                for ch, count in sorted(alpha_only.items(), key=lambda x: -x[1]):
                    pct = count / alpha_total * 100
                    bar = '█' * int(pct / 2)
                    lines.append(f"  {ch}: {count:4d} ({pct:5.1f}%) {bar}")

            lines.append("")
            lines.append("英语参考频率: ETAOINSHRDLCUMWFGYPBVKJXQZ")
            sorted_by_freq = "".join(k for k, v in sorted(alpha_only.items(), key=lambda x: -x[1]))
            lines.append(f"本文按频率: {sorted_by_freq}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def entropy_calculate(text: str) -> str:
        """信息熵计算(Shannon entropy)"""
        try:
            if not text:
                return "空文本，熵为0"
            total = len(text)
            counter = Counter(text)
            entropy = 0.0
            for count in counter.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)
            max_entropy = math.log2(len(counter)) if len(counter) > 1 else 0
            return (f"文本长度: {total}\n"
                    f"不同字符数: {len(counter)}\n"
                    f"Shannon熵: {entropy:.4f} bits/symbol\n"
                    f"最大可能熵: {max_entropy:.4f} bits/symbol\n"
                    f"归一化熵: {entropy/max_entropy:.4f}" if max_entropy > 0 else
                    f"文本长度: {total}\n不同字符数: {len(counter)}\nShannon熵: {entropy:.4f} bits/symbol")
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def string_reverse(text: str) -> str:
        """字符串反转"""
        try:
            return text[::-1]
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def char_info(text: str) -> str:
        """字符ASCII/Unicode信息。显示每个字符的编码值"""
        try:
            lines = []
            for ch in text:
                code = ord(ch)
                line = f"'{ch}' -> Dec:{code} Hex:0x{code:04x} Oct:0{code:03o}"
                if code < 128:
                    line += f" ASCII"
                lines.append(line)
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def string_transform(text: str, transform: str = "upper") -> str:
        """字符串变换。transform: upper/lower/swapcase/title/capitalize/strip/reverse_words/remove_spaces"""
        try:
            transforms = {
                "upper": text.upper,
                "lower": text.lower,
                "swapcase": text.swapcase,
                "title": text.title,
                "capitalize": text.capitalize,
                "strip": text.strip,
                "reverse_words": lambda: " ".join(text.split()[::-1]),
                "remove_spaces": lambda: text.replace(" ", ""),
            }
            if transform in transforms:
                return transforms[transform]()
            return f"错误: 不支持的变换 {transform}。可用: {', '.join(transforms.keys())}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def pattern_detect(text: str) -> str:
        """检测文本中的编码模式(hex/base64/base32/binary等)"""
        try:
            results = []
            if re.fullmatch(r'[0-9a-fA-F\s]+', text) and len(text.replace(' ', '')) % 2 == 0:
                results.append("可能是十六进制编码")
            if re.fullmatch(r'[A-Za-z0-9+/=\s]+', text) and len(text.strip()) % 4 <= 2:
                try:
                    base64.b64decode(text.strip())
                    results.append("可能是Base64编码")
                except Exception:
                    pass
            if re.fullmatch(r'[A-Z2-7=\s]+', text.upper()):
                results.append("可能是Base32编码")
            if re.fullmatch(r'[01\s]+', text):
                results.append("可能是二进制编码")
            if re.fullmatch(r'[0-7\s]+', text):
                results.append("可能是八进制编码")
            if re.fullmatch(r'[\d\s]+', text):
                results.append("可能是十进制ASCII编码")
            if re.fullmatch(r'[.\-/\s]+', text):
                results.append("可能是摩尔斯电码")
            if re.fullmatch(r'[A-Z\s]+', text):
                results.append("可能是大写字母替换密码/凯撒密码")
            if '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text):
                results.append("可能是URL编码")
            if '&#' in text or '&lt;' in text or '&gt;' in text or '&amp;' in text:
                results.append("可能是HTML实体编码")
            if re.search(r'\\u[0-9a-fA-F]{4}', text):
                results.append("可能是Unicode转义")
            if re.search(r'eyJ[A-Za-z0-9_-]+\.', text):
                results.append("可能是JWT令牌")
            if not results:
                results.append("未检测到明显的编码模式")
            return "\n".join(results)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hex_dump(data: str, input_format: str = "text") -> str:
        """十六进制转储分析。input_format: text/hex"""
        try:
            if input_format == "hex":
                raw = bytes.fromhex(data.replace(" ", ""))
            else:
                raw = data.encode('utf-8')
            lines = []
            for offset in range(0, len(raw), 16):
                chunk = raw[offset:offset + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                hex_part = hex_part.ljust(48)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
            lines.append(f"总字节数: {len(raw)}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"
