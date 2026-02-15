import math

from sympy import integer_nthroot
from sympy.ntheory.modular import crt


def register(mcp):

    @mcp.tool()
    def rsa_wiener_attack(n: str, e: str) -> str:
        """Wiener攻击(适用于小私钥指数d)。利用e/n的连分数展开恢复d。输入为十进制字符串"""
        try:
            n_val = int(n)
            e_val = int(e)

            def continued_fraction(a, b):
                cf = []
                while b:
                    q, r = divmod(a, b)
                    cf.append(q)
                    a, b = b, r
                return cf

            def convergents(cf):
                convs = []
                h_prev, h_curr = 0, 1
                k_prev, k_curr = 1, 0
                for a in cf:
                    h_prev, h_curr = h_curr, a * h_curr + h_prev
                    k_prev, k_curr = k_curr, a * k_curr + k_prev
                    convs.append((h_curr, k_curr))
                return convs

            cf = continued_fraction(e_val, n_val)
            for k, d in convergents(cf):
                if k == 0:
                    continue
                if (e_val * d - 1) % k != 0:
                    continue
                phi = (e_val * d - 1) // k
                s = n_val - phi + 1
                discriminant = s * s - 4 * n_val
                if discriminant < 0:
                    continue
                sqrt_disc, is_perfect = integer_nthroot(discriminant, 2)
                if not is_perfect:
                    continue
                p = (s + sqrt_disc) // 2
                q = (s - sqrt_disc) // 2
                if p * q == n_val:
                    return (f"攻击成功!\n"
                            f"d = {d}\n"
                            f"p = {p}\n"
                            f"q = {q}\n"
                            f"phi(n) = {phi}")
            return "Wiener攻击失败: d可能不够小"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_fermat_factor(n: str, max_iterations: int = 1000000) -> str:
        """Fermat分解(适用于p和q接近的情况)。输入为十进制字符串"""
        try:
            n_val = int(n)
            a, exact = integer_nthroot(n_val, 2)
            if exact:
                return f"n是完全平方数: {a}^2"
            a += 1
            for i in range(max_iterations):
                b2 = a * a - n_val
                b, exact = integer_nthroot(b2, 2)
                if exact:
                    p = a + b
                    q = a - b
                    return (f"分解成功!\n"
                            f"p = {p}\n"
                            f"q = {q}\n"
                            f"迭代次数: {i + 1}")
                a += 1
            return f"在{max_iterations}次迭代内未能分解"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_common_modulus(n: str, e1: str, e2: str, c1: str, c2: str) -> str:
        """RSA共模攻击。同一明文用同一n但不同e加密。输入为十进制字符串"""
        try:
            n_val = int(n)
            e1_val = int(e1)
            e2_val = int(e2)
            c1_val = int(c1)
            c2_val = int(c2)

            def ext_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                g, x, y = ext_gcd(b % a, a)
                return g, y - (b // a) * x, x

            g, s, t = ext_gcd(e1_val, e2_val)
            if g != 1:
                return f"错误: gcd(e1, e2) = {g} != 1，共模攻击不适用"

            c1_use = c1_val
            c2_use = c2_val
            s_use = s
            t_use = t
            if s < 0:
                c1_use = pow(c1_val, -1, n_val)
                s_use = -s
            if t < 0:
                c2_use = pow(c2_val, -1, n_val)
                t_use = -t

            m = (pow(c1_use, s_use, n_val) * pow(c2_use, t_use, n_val)) % n_val
            m_hex = hex(m)[2:]
            if len(m_hex) % 2:
                m_hex = '0' + m_hex
            try:
                m_text = bytes.fromhex(m_hex).decode('utf-8', errors='replace')
            except Exception:
                m_text = ""

            lines = [f"攻击成功!", f"m (十进制) = {m}", f"m (hex) = {m_hex}"]
            if m_text and all(32 <= ord(c) < 127 for c in m_text):
                lines.append(f"m (文本) = {m_text}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_hastad_broadcast(e: str, data: str) -> str:
        """Hastad广播攻击。同一明文用小e和不同n加密。data格式: n1,c1;n2,c2;... 输入为十进制"""
        try:
            e_val = int(e)
            pairs = []
            for pair in data.strip().split(";"):
                parts = pair.strip().split(",")
                if len(parts) != 2:
                    return "错误: data格式应为 n1,c1;n2,c2;..."
                pairs.append((int(parts[0].strip()), int(parts[1].strip())))

            if len(pairs) < e_val:
                return f"错误: 需要至少{e_val}组(n,c)数据"

            ns = [p[0] for p in pairs[:e_val]]
            cs = [p[1] for p in pairs[:e_val]]

            result = crt(ns, cs)
            if result is None:
                return "错误: CRT无解"

            combined, mod = result
            root, exact = integer_nthroot(int(combined), e_val)
            if exact:
                m_hex = hex(root)[2:]
                if len(m_hex) % 2:
                    m_hex = '0' + m_hex
                try:
                    m_text = bytes.fromhex(m_hex).decode('utf-8', errors='replace')
                except Exception:
                    m_text = ""
                lines = [f"攻击成功!", f"m (十进制) = {root}", f"m (hex) = {m_hex}"]
                if m_text and all(32 <= ord(c) < 127 for c in m_text):
                    lines.append(f"m (文本) = {m_text}")
                return "\n".join(lines)
            else:
                return f"开{e_val}次方根不精确，可能需要更多数据或攻击不适用\n近似值: {root}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_pollard_p1(n: str, B: int = 100000) -> str:
        """Pollard p-1分解(适用于p-1有小因子的情况)。B: 光滑度上界"""
        try:
            n_val = int(n)
            a = 2
            for j in range(2, B + 1):
                a = pow(a, j, n_val)
                if j % 500 == 0:
                    g = math.gcd(a - 1, n_val)
                    if 1 < g < n_val:
                        q = n_val // g
                        return (f"分解成功!\n"
                                f"p = {g}\n"
                                f"q = {q}\n"
                                f"B = {j}")
            g = math.gcd(a - 1, n_val)
            if 1 < g < n_val:
                q = n_val // g
                return (f"分解成功!\n"
                        f"p = {g}\n"
                        f"q = {q}\n"
                        f"B = {B}")
            return f"在B={B}范围内未能分解"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_pollard_rho(n: str, max_iterations: int = 1000000) -> str:
        """Pollard rho因数分解。适用于中等大小的因子"""
        try:
            n_val = int(n)
            if n_val % 2 == 0:
                return f"分解成功!\np = 2\nq = {n_val // 2}"

            for c in range(1, 100):
                x = 2
                y = 2
                d = 1
                count = 0
                while d == 1 and count < max_iterations:
                    x = (x * x + c) % n_val
                    y = (y * y + c) % n_val
                    y = (y * y + c) % n_val
                    d = math.gcd(abs(x - y), n_val)
                    count += 1

                if 1 < d < n_val:
                    q = n_val // d
                    return (f"分解成功!\n"
                            f"p = {d}\n"
                            f"q = {q}\n"
                            f"方法: Pollard rho (c={c}, 迭代{count}次)")

            return f"Pollard rho在尝试所有参数后未能分解"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def rsa_small_e_attack(e: str, c: str, n: str = "") -> str:
        """RSA小公钥指数攻击。当m^e < n时直接开e次方根，也尝试m^e = c + k*n (k较小)"""
        try:
            e_val = int(e)
            c_val = int(c)
            n_val = int(n) if n else 0

            root, exact = integer_nthroot(c_val, e_val)
            if exact:
                m_hex = hex(root)[2:]
                if len(m_hex) % 2:
                    m_hex = '0' + m_hex
                try:
                    m_text = bytes.fromhex(m_hex).decode('utf-8', errors='replace')
                except Exception:
                    m_text = ""
                lines = [f"攻击成功! (直接开根)", f"m (十进制) = {root}", f"m (hex) = {m_hex}"]
                if m_text and all(32 <= ord(ch) < 127 for ch in m_text):
                    lines.append(f"m (文本) = {m_text}")
                return "\n".join(lines)

            if n_val:
                for k in range(1, 100000):
                    root, exact = integer_nthroot(c_val + k * n_val, e_val)
                    if exact:
                        m_hex = hex(root)[2:]
                        if len(m_hex) % 2:
                            m_hex = '0' + m_hex
                        try:
                            m_text = bytes.fromhex(m_hex).decode('utf-8', errors='replace')
                        except Exception:
                            m_text = ""
                        lines = [f"攻击成功! (k={k})", f"m (十进制) = {root}", f"m (hex) = {m_hex}"]
                        if m_text and all(32 <= ord(ch) < 127 for ch in m_text):
                            lines.append(f"m (文本) = {m_text}")
                        return "\n".join(lines)

            return "攻击失败: 无法通过小指数攻击恢复明文"
        except Exception as e:
            return f"错误: {e}"
