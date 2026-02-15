import struct
import time
import datetime
import uuid as uuid_mod
import re
import secrets
import string


def register(mcp):

    @mcp.tool()
    def file_magic_identify(hex_data: str) -> str:
        """文件头魔数识别。hex_data: 文件开头的hex字符串"""
        try:
            raw = bytes.fromhex(hex_data.replace(" ", ""))
            SIGNATURES = [
                (b'\x89PNG\r\n\x1a\n', "PNG图片"),
                (b'\xff\xd8\xff', "JPEG图片"),
                (b'GIF87a', "GIF图片 (87a)"),
                (b'GIF89a', "GIF图片 (89a)"),
                (b'BM', "BMP图片"),
                (b'PK\x03\x04', "ZIP压缩包 / DOCX / XLSX / JAR"),
                (b'PK\x05\x06', "ZIP压缩包 (空)"),
                (b'\x1f\x8b', "GZIP压缩"),
                (b'Rar!\x1a\x07', "RAR压缩包"),
                (b'\x50\x4b\x03\x04', "ZIP/Office Open XML"),
                (b'%PDF', "PDF文档"),
                (b'\x7fELF', "ELF可执行文件 (Linux)"),
                (b'MZ', "PE可执行文件 (Windows EXE/DLL)"),
                (b'\xca\xfe\xba\xbe', "Java Class文件 / Mach-O Fat Binary"),
                (b'\xfe\xed\xfa\xce', "Mach-O 32-bit"),
                (b'\xfe\xed\xfa\xcf', "Mach-O 64-bit"),
                (b'\xce\xfa\xed\xfe', "Mach-O 32-bit (反序)"),
                (b'\xcf\xfa\xed\xfe', "Mach-O 64-bit (反序)"),
                (b'\x00\x00\x00\x1c\x66\x74\x79\x70', "MP4视频"),
                (b'\x00\x00\x00\x18\x66\x74\x79\x70', "MP4视频"),
                (b'\x00\x00\x00\x20\x66\x74\x79\x70', "MP4视频"),
                (b'\x1a\x45\xdf\xa3', "MKV/WebM视频"),
                (b'RIFF', "RIFF格式 (AVI/WAV)"),
                (b'OggS', "OGG音频"),
                (b'fLaC', "FLAC音频"),
                (b'ID3', "MP3音频 (ID3标签)"),
                (b'\xff\xfb', "MP3音频"),
                (b'\xff\xf3', "MP3音频"),
                (b'\xff\xf2', "MP3音频"),
                (b'SQLite format 3\x00', "SQLite数据库"),
                (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', "MS Office (OLE2) DOC/XLS/PPT"),
                (b'<?xml', "XML文档"),
                (b'<!DOCTYPE', "HTML文档"),
                (b'<html', "HTML文档"),
                (b'\x00\x61\x73\x6d', "WebAssembly"),
                (b'\x37\x7a\xbc\xaf\x27\x1c', "7-Zip压缩包"),
                (b'BZh', "BZip2压缩"),
                (b'\xfd\x37\x7a\x58\x5a\x00', "XZ压缩"),
            ]

            matches = []
            for sig, desc in SIGNATURES:
                if raw[:len(sig)] == sig:
                    matches.append(desc)

            hex_preview = " ".join(f"{b:02x}" for b in raw[:32])
            ascii_preview = "".join(chr(b) if 32 <= b < 127 else '.' for b in raw[:32])

            lines = [f"Hex: {hex_preview}", f"ASCII: {ascii_preview}", ""]
            if matches:
                lines.append(f"识别结果: {', '.join(matches)}")
            else:
                lines.append("未能识别文件类型")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def timestamp_convert(value: str, mode: str = "to_human") -> str:
        """Unix时间戳转换。mode: to_human(时间戳->可读)/to_unix(可读->时间戳)/now(当前时间戳)"""
        try:
            if mode == "now":
                now = time.time()
                dt = datetime.datetime.fromtimestamp(now)
                utc = datetime.datetime.utcfromtimestamp(now)
                return (f"当前Unix时间戳: {int(now)}\n"
                        f"毫秒时间戳: {int(now * 1000)}\n"
                        f"本地时间: {dt.isoformat()}\n"
                        f"UTC时间: {utc.isoformat()}Z")
            elif mode == "to_human":
                ts = float(value)
                if ts > 1e12:
                    ts = ts / 1000
                dt = datetime.datetime.fromtimestamp(ts)
                utc = datetime.datetime.utcfromtimestamp(ts)
                return (f"时间戳: {value}\n"
                        f"本地时间: {dt.isoformat()}\n"
                        f"UTC时间: {utc.isoformat()}Z")
            elif mode == "to_unix":
                for fmt in [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d",
                    "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d",
                    "%d/%m/%Y %H:%M:%S",
                ]:
                    try:
                        dt = datetime.datetime.strptime(value, fmt)
                        ts = int(dt.timestamp())
                        return f"时间: {value}\nUnix时间戳: {ts}\n毫秒时间戳: {ts * 1000}"
                    except ValueError:
                        continue
                return "错误: 无法解析时间格式"
            else:
                return f"错误: 不支持的模式 {mode}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def uuid_generate(version: int = 4, namespace: str = "", name: str = "") -> str:
        """UUID生成与解析。version: 1/3/4/5。v3/v5需要namespace和name"""
        try:
            if version == 1:
                u = uuid_mod.uuid1()
            elif version == 3:
                ns_map = {
                    "dns": uuid_mod.NAMESPACE_DNS,
                    "url": uuid_mod.NAMESPACE_URL,
                    "oid": uuid_mod.NAMESPACE_OID,
                    "x500": uuid_mod.NAMESPACE_X500,
                }
                ns = ns_map.get(namespace.lower(), uuid_mod.NAMESPACE_DNS)
                u = uuid_mod.uuid3(ns, name)
            elif version == 4:
                u = uuid_mod.uuid4()
            elif version == 5:
                ns_map = {
                    "dns": uuid_mod.NAMESPACE_DNS,
                    "url": uuid_mod.NAMESPACE_URL,
                    "oid": uuid_mod.NAMESPACE_OID,
                    "x500": uuid_mod.NAMESPACE_X500,
                }
                ns = ns_map.get(namespace.lower(), uuid_mod.NAMESPACE_DNS)
                u = uuid_mod.uuid5(ns, name)
            else:
                return f"错误: 不支持的版本 {version}"

            return (f"UUID: {u}\n"
                    f"版本: {u.version}\n"
                    f"变体: {u.variant}\n"
                    f"Hex: {u.hex}\n"
                    f"整数: {u.int}")
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def random_generate(length: int = 32, mode: str = "hex") -> str:
        """安全随机数/字符串生成。mode: hex/bytes/alphanumeric/digits/password/base64"""
        try:
            if mode == "hex":
                return secrets.token_hex(length)
            elif mode == "bytes":
                return secrets.token_bytes(length).hex()
            elif mode == "alphanumeric":
                alphabet = string.ascii_letters + string.digits
                return "".join(secrets.choice(alphabet) for _ in range(length))
            elif mode == "digits":
                return "".join(secrets.choice(string.digits) for _ in range(length))
            elif mode == "password":
                alphabet = string.ascii_letters + string.digits + string.punctuation
                return "".join(secrets.choice(alphabet) for _ in range(length))
            elif mode == "base64":
                return secrets.token_urlsafe(length)
            else:
                return f"错误: 不支持的模式 {mode}。可用: hex/bytes/alphanumeric/digits/password/base64"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def regex_test(pattern: str, text: str, flags: str = "") -> str:
        """正则表达式测试。flags: i(忽略大小写)/m(多行)/s(dotall)"""
        try:
            flag_val = 0
            if 'i' in flags:
                flag_val |= re.IGNORECASE
            if 'm' in flags:
                flag_val |= re.MULTILINE
            if 's' in flags:
                flag_val |= re.DOTALL

            matches = list(re.finditer(pattern, text, flag_val))
            if not matches:
                return f"模式: {pattern}\n未找到匹配"

            lines = [f"模式: {pattern}", f"匹配数: {len(matches)}", ""]
            for i, m in enumerate(matches):
                lines.append(f"匹配 {i+1}: '{m.group()}' (位置: {m.start()}-{m.end()})")
                if m.groups():
                    for j, g in enumerate(m.groups(), 1):
                        lines.append(f"  组 {j}: '{g}'")
                if m.groupdict():
                    for name, val in m.groupdict().items():
                        lines.append(f"  命名组 '{name}': '{val}'")
            return "\n".join(lines)
        except re.error as e:
            return f"正则表达式错误: {e}"
        except Exception as e:
            return f"错误: {e}"
