import string
from math import gcd
from collections import Counter


def register(mcp):

    @mcp.tool()
    def caesar_cipher(text: str, shift: int = 3, mode: str = "encrypt") -> str:
        """凯撒密码加解密。mode: encrypt/decrypt，shift: 偏移量(1-25)"""
        try:
            if mode == "decrypt":
                shift = -shift
            result = []
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    result.append(chr((ord(ch) - base + shift) % 26 + base))
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def caesar_bruteforce(text: str) -> str:
        """凯撒密码暴力破解，输出所有25种偏移结果"""
        try:
            lines = []
            for shift in range(1, 26):
                decrypted = caesar_cipher(text, shift, "decrypt")
                lines.append(f"Shift {shift:2d}: {decrypted}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rot13(text: str) -> str:
        """ROT13编码/解码"""
        try:
            return caesar_cipher(text, 13)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rot_n(text: str, n: int = 13) -> str:
        """ROT-N任意偏移编码/解码"""
        try:
            return caesar_cipher(text, n)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rot47(text: str) -> str:
        """ROT47编码/解码 (ASCII 33-126)"""
        try:
            result = []
            for ch in text:
                c = ord(ch)
                if 33 <= c <= 126:
                    result.append(chr(33 + (c - 33 + 47) % 94))
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def vigenere_cipher(text: str, key: str, mode: str = "encrypt") -> str:
        """维吉尼亚密码加解密。key: 密钥字母串，mode: encrypt/decrypt"""
        try:
            key = key.upper()
            result = []
            ki = 0
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    k = ord(key[ki % len(key)]) - ord('A')
                    if mode == "decrypt":
                        k = -k
                    result.append(chr((ord(ch) - base + k) % 26 + base))
                    ki += 1
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def atbash_cipher(text: str) -> str:
        """埃特巴什密码 (A↔Z, B↔Y, ...)"""
        try:
            result = []
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    result.append(chr(base + 25 - (ord(ch) - base)))
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rail_fence_cipher(text: str, rails: int = 3, mode: str = "encrypt") -> str:
        """栅栏密码加解密。rails: 栏数，mode: encrypt/decrypt"""
        try:
            if rails < 2:
                return "错误: 栏数必须>=2"
            if mode == "encrypt":
                fence = [[] for _ in range(rails)]
                rail = 0
                direction = 1
                for ch in text:
                    fence[rail].append(ch)
                    if rail == 0:
                        direction = 1
                    elif rail == rails - 1:
                        direction = -1
                    rail += direction
                return "".join("".join(row) for row in fence)
            else:
                n = len(text)
                pattern = []
                rail = 0
                direction = 1
                for i in range(n):
                    pattern.append(rail)
                    if rail == 0:
                        direction = 1
                    elif rail == rails - 1:
                        direction = -1
                    rail += direction
                indices = sorted(range(n), key=lambda i: pattern[i])
                result = [''] * n
                for i, idx in enumerate(indices):
                    result[idx] = text[i]
                return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rail_fence_bruteforce(text: str) -> str:
        """栅栏密码暴力破解，尝试2到text长度/2的栏数"""
        try:
            lines = []
            max_rails = min(len(text), 20)
            for r in range(2, max_rails + 1):
                dec = rail_fence_cipher(text, r, "decrypt")
                lines.append(f"Rails {r:2d}: {dec}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def affine_cipher(text: str, a: int = 5, b: int = 8, mode: str = "encrypt") -> str:
        """仿射密码加解密。E(x)=(a*x+b)mod26, a必须与26互素。mode: encrypt/decrypt"""
        try:
            if gcd(a, 26) != 1:
                return f"错误: a={a} 与26不互素，无法使用"
            result = []
            if mode == "decrypt":
                a_inv = pow(a, -1, 26)
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    x = ord(ch) - base
                    if mode == "encrypt":
                        result.append(chr((a * x + b) % 26 + base))
                    else:
                        result.append(chr((a_inv * (x - b)) % 26 + base))
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def playfair_cipher(text: str, key: str = "KEYWORD", mode: str = "encrypt") -> str:
        """Playfair密码加解密。key: 密钥，mode: encrypt/decrypt。J合并到I"""
        try:
            key = key.upper().replace("J", "I")
            seen = set()
            matrix = []
            for ch in key + string.ascii_uppercase.replace("J", ""):
                if ch not in seen and ch.isalpha():
                    seen.add(ch)
                    matrix.append(ch)

            def pos(c):
                idx = matrix.index(c)
                return idx // 5, idx % 5

            text_clean = text.upper().replace("J", "I")
            text_clean = "".join(c for c in text_clean if c.isalpha())

            pairs = []
            i = 0
            while i < len(text_clean):
                a = text_clean[i]
                if i + 1 < len(text_clean):
                    b = text_clean[i + 1]
                    if a == b:
                        pairs.append((a, 'X'))
                        i += 1
                    else:
                        pairs.append((a, b))
                        i += 2
                else:
                    pairs.append((a, 'X'))
                    i += 1

            result = []
            for a, b in pairs:
                r1, c1 = pos(a)
                r2, c2 = pos(b)
                if r1 == r2:
                    d = 1 if mode == "encrypt" else -1
                    result.append(matrix[r1 * 5 + (c1 + d) % 5])
                    result.append(matrix[r2 * 5 + (c2 + d) % 5])
                elif c1 == c2:
                    d = 1 if mode == "encrypt" else -1
                    result.append(matrix[((r1 + d) % 5) * 5 + c1])
                    result.append(matrix[((r2 + d) % 5) * 5 + c2])
                else:
                    result.append(matrix[r1 * 5 + c2])
                    result.append(matrix[r2 * 5 + c1])
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def columnar_transposition(text: str, key: str, mode: str = "encrypt") -> str:
        """列置换密码加解密。key: 数字或字母密钥"""
        try:
            if key.isdigit():
                order = [int(c) - 1 for c in key]
            else:
                sorted_key = sorted(enumerate(key.upper()), key=lambda x: x[1])
                order = [0] * len(key)
                for rank, (orig_idx, _) in enumerate(sorted_key):
                    order[orig_idx] = rank

            ncols = len(order)
            if mode == "encrypt":
                nrows = -(-len(text) // ncols)
                padded = text.ljust(nrows * ncols)
                grid = [padded[i * ncols:(i + 1) * ncols] for i in range(nrows)]
                result = []
                for col in sorted(range(ncols), key=lambda c: order[c]):
                    for row in grid:
                        result.append(row[col])
                return "".join(result)
            else:
                n = len(text)
                nrows = -(-n // ncols)
                full_cols = n % ncols if n % ncols != 0 else ncols
                col_order = sorted(range(ncols), key=lambda c: order[c])
                cols_data = {}
                idx = 0
                for col in col_order:
                    col_len = nrows if col < full_cols else nrows - 1
                    cols_data[col] = text[idx:idx + col_len]
                    idx += col_len
                result = []
                for r in range(nrows):
                    for c in range(ncols):
                        if r < len(cols_data.get(c, "")):
                            result.append(cols_data[c][r])
                return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def bacon_cipher(text: str, mode: str = "encode") -> str:
        """培根密码编解码。mode: encode(文本->AB序列)/decode(AB序列->文本)"""
        try:
            bacon_table = {}
            for i, ch in enumerate("ABCDEFGHIKLMNOPQRSTUVWXYZ"):
                bacon_table[ch] = format(i, '05b').replace('0', 'A').replace('1', 'B')
            if mode == "encode":
                result = []
                for ch in text.upper():
                    if ch == 'J':
                        ch = 'I'
                    if ch in bacon_table:
                        result.append(bacon_table[ch])
                return " ".join(result)
            else:
                rev = {v: k for k, v in bacon_table.items()}
                clean = text.upper().replace(" ", "")
                result = []
                for i in range(0, len(clean) - 4, 5):
                    code = clean[i:i + 5]
                    if code in rev:
                        result.append(rev[code])
                    else:
                        result.append("?")
                return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def polybius_square(text: str, mode: str = "encode") -> str:
        """波利比奥斯方阵编解码。5x5方阵(I/J合并)，mode: encode/decode"""
        try:
            grid = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
            if mode == "encode":
                result = []
                for ch in text.upper():
                    if ch == 'J':
                        ch = 'I'
                    if ch in grid:
                        idx = grid.index(ch)
                        result.append(f"{idx // 5 + 1}{idx % 5 + 1}")
                    elif ch == ' ':
                        result.append(" ")
                return " ".join(result) if " " not in "".join(result) else "".join(result)
            else:
                digits = [c for c in text if c.isdigit()]
                result = []
                for i in range(0, len(digits) - 1, 2):
                    r, c = int(digits[i]) - 1, int(digits[i + 1]) - 1
                    if 0 <= r < 5 and 0 <= c < 5:
                        result.append(grid[r * 5 + c])
                    else:
                        result.append("?")
                return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def beaufort_cipher(text: str, key: str) -> str:
        """Beaufort密码(对称，加密=解密)。E(x)=(K-P)mod26"""
        try:
            key = key.upper()
            result = []
            ki = 0
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    k = ord(key[ki % len(key)]) - ord('A')
                    p = ord(ch.upper()) - ord('A')
                    enc = (k - p) % 26
                    result.append(chr(enc + base))
                    ki += 1
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def autokey_cipher(text: str, key: str, mode: str = "encrypt") -> str:
        """自动密钥密码加解密。密钥后接明文自身"""
        try:
            key = key.upper()
            result = []
            full_key = list(key)
            ki = 0
            for ch in text:
                if ch.isalpha():
                    base = ord('A') if ch.isupper() else ord('a')
                    if ki < len(full_key):
                        k = ord(full_key[ki]) - ord('A')
                    else:
                        k = 0
                    p = ord(ch.upper()) - ord('A')
                    if mode == "encrypt":
                        enc = (p + k) % 26
                        result.append(chr(enc + base))
                        full_key.append(ch.upper())
                    else:
                        dec = (p - k) % 26
                        dec_ch = chr(dec + base)
                        result.append(dec_ch)
                        full_key.append(dec_ch.upper())
                    ki += 1
                else:
                    result.append(ch)
            return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def keyword_cipher(text: str, keyword: str, mode: str = "encrypt") -> str:
        """关键字替换密码。用关键字生成替换字母表"""
        try:
            keyword = keyword.upper()
            seen = set()
            alphabet = []
            for ch in keyword:
                if ch.isalpha() and ch not in seen:
                    seen.add(ch)
                    alphabet.append(ch)
            for ch in string.ascii_uppercase:
                if ch not in seen:
                    alphabet.append(ch)
            cipher_alpha = "".join(alphabet)
            plain_alpha = string.ascii_uppercase
            if mode == "encrypt":
                table = str.maketrans(plain_alpha + plain_alpha.lower(),
                                       cipher_alpha + cipher_alpha.lower())
            else:
                table = str.maketrans(cipher_alpha + cipher_alpha.lower(),
                                       plain_alpha + plain_alpha.lower())
            return text.translate(table)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def vigenere_break(text: str, max_key_length: int = 30) -> str:
        """维吉尼亚密码自动破解。使用重合指数(IoC)检测密钥长度，频率分析恢复密钥"""
        try:
            clean = [c.upper() for c in text if c.isalpha()]
            if len(clean) < 20:
                return "错误: 文本太短，至少需要20个字母"

            eng_freq = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                        0.00978, 0.02361, 0.00150, 0.01974, 0.00074]

            def calc_ioc(s):
                if len(s) < 2:
                    return 0
                freq = Counter(s)
                n = len(s)
                return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

            def chi_squared(observed, expected):
                return sum((o - e) ** 2 / e for o, e in zip(observed, expected) if e > 0)

            ioc_results = []
            for kl in range(1, min(max_key_length, len(clean) // 2) + 1):
                groups = [[] for _ in range(kl)]
                for i, c in enumerate(clean):
                    groups[i % kl].append(c)
                avg_ioc = sum(calc_ioc(g) for g in groups) / kl
                ioc_results.append((kl, avg_ioc))

            ioc_sorted = sorted(ioc_results, key=lambda x: abs(x[1] - 0.0667))
            best_kl = ioc_sorted[0][0]

            groups = [[] for _ in range(best_kl)]
            for i, c in enumerate(clean):
                groups[i % best_kl].append(c)

            key = []
            for group in groups:
                best_shift = 0
                best_chi = float('inf')
                n = len(group)
                for shift in range(26):
                    shifted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
                    freq = Counter(shifted)
                    observed = [freq.get(chr(i + ord('A')), 0) / n for i in range(26)]
                    chi = chi_squared(observed, eng_freq)
                    if chi < best_chi:
                        best_chi = chi
                        best_shift = shift
                key.append(chr(best_shift + ord('A')))

            key_str = "".join(key)
            decrypted = []
            ki = 0
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    k = ord(key[ki % len(key)]) - ord('A')
                    decrypted.append(chr((ord(c) - base - k) % 26 + base))
                    ki += 1
                else:
                    decrypted.append(c)

            lines = [
                f"推测密钥长度: {best_kl}",
                f"推测密钥: {key_str}",
                "",
                "IoC分析 (前5个最可能的密钥长度):",
            ]
            for kl, ioc in ioc_sorted[:5]:
                marker = " <--" if kl == best_kl else ""
                lines.append(f"  长度 {kl:2d}: IoC = {ioc:.6f}{marker}")
            lines.append("")
            lines.append("解密结果:")
            lines.append("".join(decrypted))

            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"
