import json
import math
from fractions import Fraction


def register(mcp):

    def _mat_mult(A, B, mod):
        n, m_dim, p = len(A), len(B), len(B[0])
        C = [[0] * p for _ in range(n)]
        for i in range(n):
            for j in range(p):
                s = 0
                for k in range(m_dim):
                    s += A[i][k] * B[k][j]
                C[i][j] = s % mod
        return C

    def _mat_to_str(M, label=""):
        lines = [label] if label else []
        for row in M:
            lines.append("  [" + ", ".join(str(x) for x in row) + "]")
        return "\n".join(lines)

    def _mat_inv_mod(A, mod):
        """Compute matrix inverse mod m. Returns None if not invertible."""
        n = len(A)
        aug = [[A[i][j] % mod for j in range(n)] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
        for col in range(n):
            pivot = -1
            for row in range(col, n):
                if aug[row][col] % mod != 0:
                    try:
                        pow(aug[row][col], -1, mod)
                        pivot = row
                        break
                    except (ValueError, ZeroDivisionError):
                        continue
            if pivot == -1:
                return None
            aug[col], aug[pivot] = aug[pivot], aug[col]
            inv_pivot = pow(aug[col][col], -1, mod)
            aug[col] = [(x * inv_pivot) % mod for x in aug[col]]
            for row in range(n):
                if row != col and aug[row][col] != 0:
                    factor = aug[row][col]
                    aug[row] = [(aug[row][j] - factor * aug[col][j]) % mod for j in range(2 * n)]
        return [[aug[i][j + n] for j in range(n)] for i in range(n)]

    @mcp.tool()
    def matrix_mod_operation(matrix_a: str, matrix_b: str = "", modulus: str = "26", operation: str = "multiply") -> str:
        """矩阵模运算。matrix格式: [[1,2],[3,4]]。operation: multiply/add/power。modulus为模数"""
        try:
            A = json.loads(matrix_a)
            mod = int(modulus)

            if operation == "power":
                exp = int(matrix_b) if matrix_b else 2
                n = len(A)
                result = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
                base = [[A[i][j] % mod for j in range(n)] for i in range(n)]
                while exp > 0:
                    if exp & 1:
                        result = _mat_mult(result, base, mod)
                    base = _mat_mult(base, base, mod)
                    exp >>= 1
                return _mat_to_str(result, f"A^exp mod {mod}")

            B = json.loads(matrix_b)

            if operation == "multiply":
                C = _mat_mult(A, B, mod)
                return _mat_to_str(C, f"A * B mod {mod}")
            elif operation == "add":
                n, m_dim = len(A), len(A[0])
                C = [[(A[i][j] + B[i][j]) % mod for j in range(m_dim)] for i in range(n)]
                return _mat_to_str(C, f"A + B mod {mod}")
            else:
                return f"错误: 不支持的操作 {operation}。可用: multiply/add/power"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def matrix_inverse_mod(matrix: str, modulus: str = "26") -> str:
        """矩阵求逆 mod m。matrix格式: [[1,2],[3,4]]"""
        try:
            A = json.loads(matrix)
            mod = int(modulus)
            inv = _mat_inv_mod(A, mod)
            if inv is None:
                return "错误: 矩阵在该模下不可逆"
            return _mat_to_str(inv, f"逆矩阵 mod {mod}")
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def matrix_det_mod(matrix: str, modulus: str = "26") -> str:
        """矩阵行列式 mod m"""
        try:
            A = json.loads(matrix)
            mod = int(modulus)
            n = len(A)
            M = [[A[i][j] % mod for j in range(n)] for i in range(n)]
            det = 1
            swaps = 0

            for col in range(n):
                pivot = -1
                for row in range(col, n):
                    if M[row][col] % mod != 0:
                        pivot = row
                        break
                if pivot == -1:
                    return f"det = 0 (mod {mod})"
                if pivot != col:
                    M[col], M[pivot] = M[pivot], M[col]
                    swaps += 1
                det = (det * M[col][col]) % mod
                try:
                    inv_pivot = pow(M[col][col], -1, mod)
                except (ValueError, ZeroDivisionError):
                    return f"det 计算遇到不可逆元素"
                for row in range(col + 1, n):
                    factor = (M[row][col] * inv_pivot) % mod
                    for j in range(n):
                        M[row][j] = (M[row][j] - factor * M[col][j]) % mod

            if swaps % 2 == 1:
                det = (-det) % mod
            return f"det = {det} (mod {mod})"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def solve_linear_mod(matrix_a: str, vector_b: str, modulus: str) -> str:
        """解线性方程组 Ax = b (mod m)。A: [[...],[...]]，b: [...]"""
        try:
            A = json.loads(matrix_a)
            b = json.loads(vector_b)
            mod = int(modulus)
            n = len(A)

            aug = [[A[i][j] % mod for j in range(n)] + [b[i] % mod] for i in range(n)]

            for col in range(n):
                pivot = -1
                for row in range(col, n):
                    if aug[row][col] % mod != 0:
                        try:
                            pow(aug[row][col], -1, mod)
                            pivot = row
                            break
                        except (ValueError, ZeroDivisionError):
                            continue
                if pivot == -1:
                    return "错误: 无唯一解"
                aug[col], aug[pivot] = aug[pivot], aug[col]
                inv_pivot = pow(aug[col][col], -1, mod)
                aug[col] = [(x * inv_pivot) % mod for x in aug[col]]
                for row in range(n):
                    if row != col and aug[row][col] != 0:
                        factor = aug[row][col]
                        aug[row] = [(aug[row][j] - factor * aug[col][j]) % mod for j in range(n + 1)]

            x = [aug[i][n] for i in range(n)]
            return f"解: x = {x} (mod {mod})"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def hill_cipher(text: str, key_matrix: str, mode: str = "encrypt", modulus: int = 26) -> str:
        """Hill密码加解密。key_matrix: [[a,b],[c,d]] (NxN方阵)，modulus默认26"""
        try:
            K = json.loads(key_matrix)
            n = len(K)
            mod = modulus

            clean = [c for c in text.upper() if c.isalpha()]
            while len(clean) % n != 0:
                clean.append('X')
            nums = [ord(c) - ord('A') for c in clean]

            if mode == "decrypt":
                K = _mat_inv_mod(K, mod)
                if K is None:
                    return "错误: 密钥矩阵在mod {}下不可逆".format(mod)

            result = []
            for i in range(0, len(nums), n):
                block = nums[i:i + n]
                out = [0] * n
                for r in range(n):
                    for c in range(n):
                        out[r] = (out[r] + K[r][c] * block[c]) % mod
                result.extend(out)

            return "".join(chr(x + ord('A')) for x in result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def lll_reduce(matrix: str, delta: str = "0.75") -> str:
        """LLL格基规约算法。matrix: [[v1_1,v1_2,...],[v2_1,v2_2,...]] 行向量。返回规约后的基"""
        try:
            B = json.loads(matrix)
            delta_val = Fraction(delta).limit_denominator(1000)
            n = len(B)
            m = len(B[0])

            B = [[Fraction(B[i][j]) for j in range(m)] for i in range(n)]

            def dot(u, v):
                return sum(a * b for a, b in zip(u, v))

            def gram_schmidt(B):
                n_gs = len(B)
                m_gs = len(B[0])
                Q = [[Fraction(0)] * m_gs for _ in range(n_gs)]
                mu = [[Fraction(0)] * n_gs for _ in range(n_gs)]
                for i in range(n_gs):
                    Q[i] = B[i][:]
                    for j in range(i):
                        denom = dot(Q[j], Q[j])
                        if denom == 0:
                            mu[i][j] = Fraction(0)
                        else:
                            mu[i][j] = dot(B[i], Q[j]) / denom
                        Q[i] = [Q[i][k] - mu[i][j] * Q[j][k] for k in range(m_gs)]
                return Q, mu

            k = 1
            while k < n:
                Q, mu = gram_schmidt(B)

                for j in range(k - 1, -1, -1):
                    if abs(mu[k][j]) > Fraction(1, 2):
                        r = round(mu[k][j])
                        B[k] = [B[k][i] - r * B[j][i] for i in range(m)]
                        Q, mu = gram_schmidt(B)

                qk_norm = dot(Q[k], Q[k])
                qk1_norm = dot(Q[k - 1], Q[k - 1])

                if qk_norm >= (delta_val - mu[k][k - 1] ** 2) * qk1_norm:
                    k += 1
                else:
                    B[k], B[k - 1] = B[k - 1], B[k]
                    k = max(k - 1, 1)

            result = [[int(B[i][j]) for j in range(m)] for i in range(n)]
            lines = ["LLL规约结果:"]
            for row in result:
                lines.append("  " + str(row))
            norms = [math.sqrt(sum(x * x for x in row)) for row in result]
            lines.append("")
            lines.append("各向量范数:")
            for i, norm in enumerate(norms):
                lines.append(f"  |v{i}| = {norm:.6f}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def berlekamp_massey(sequence: str, modulus: str = "2") -> str:
        """Berlekamp-Massey算法。从序列恢复最短LFSR。sequence: 逗号分隔的整数"""
        try:
            s = [int(x.strip()) for x in sequence.split(",")]
            mod = int(modulus)
            n = len(s)

            C = [1]
            B_poly = [1]
            L = 0
            m_step = 1
            b = 1

            for i in range(n):
                d = s[i] % mod
                for j in range(1, len(C)):
                    d = (d + C[j] * s[i - j]) % mod

                if d == 0:
                    m_step += 1
                elif 2 * L <= i:
                    T = C[:]
                    coeff = (d * pow(b, -1, mod)) % mod
                    while len(C) < len(B_poly) + m_step:
                        C.append(0)
                    for j in range(len(B_poly)):
                        C[j + m_step] = (C[j + m_step] - coeff * B_poly[j]) % mod
                    L = i + 1 - L
                    B_poly = T
                    b = d
                    m_step = 1
                else:
                    coeff = (d * pow(b, -1, mod)) % mod
                    while len(C) < len(B_poly) + m_step:
                        C.append(0)
                    for j in range(len(B_poly)):
                        C[j + m_step] = (C[j + m_step] - coeff * B_poly[j]) % mod
                    m_step += 1

            taps = [i for i in range(1, len(C)) if C[i] != 0]
            feedback = [(-C[i]) % mod for i in range(1, len(C)) if C[i] != 0]

            lines = [
                f"LFSR长度 (线性复杂度): {L}",
                f"连接多项式系数 C(x): {C}",
                f"反馈位置 (taps): {taps}",
                f"反馈系数: {feedback}",
                f"模数: {mod}",
                "",
                f"递推关系: s[n] = " + " + ".join(
                    f"{feedback[i]}*s[n-{taps[i]}]" for i in range(len(taps))
                ) + f" (mod {mod})"
            ]
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"
