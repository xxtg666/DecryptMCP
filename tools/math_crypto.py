import math

from sympy import factorint, isprime as sympy_isprime, totient, gcdex, Integer
from sympy.ntheory.modular import crt
from sympy.ntheory import discrete_log as dlog, nthroot_mod


def register(mcp):

    @mcp.tool()
    def math_eval(expression: str) -> str:
        """安全数学表达式计算器。支持+,-,*,/,**,%,//以及math模块函数"""
        try:
            allowed_names = {
                k: v for k, v in math.__dict__.items()
                if not k.startswith('_')
            }
            allowed_names.update({
                'abs': abs, 'int': int, 'float': float,
                'round': round, 'min': min, 'max': max,
                'pow': pow, 'sum': sum, 'hex': hex,
                'bin': bin, 'oct': oct,
            })
            result = eval(expression, {"__builtins__": {}}, allowed_names)
            return str(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def base_convert(number: str, from_base: int = 10, to_base: int = 16) -> str:
        """任意进制转换(2-62)。number为字符串"""
        try:
            DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            if from_base <= 36:
                n = int(number, from_base)
            else:
                n = 0
                for ch in number:
                    n = n * from_base + DIGITS.index(ch)
            if to_base == 10:
                return str(n)
            if to_base <= 36:
                result = []
                neg = n < 0
                n = abs(n)
                if n == 0:
                    return "0"
                while n > 0:
                    n, r = divmod(n, to_base)
                    result.append(DIGITS[r])
                if neg:
                    result.append('-')
                return "".join(reversed(result))
            else:
                result = []
                neg = n < 0
                n = abs(n)
                if n == 0:
                    return "0"
                while n > 0:
                    n, r = divmod(n, to_base)
                    result.append(DIGITS[r])
                if neg:
                    result.append('-')
                return "".join(reversed(result))
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def prime_factorize(n: str) -> str:
        """大整数质因数分解。n为字符串形式的整数"""
        try:
            num = int(n)
            if num < 2:
                return f"{num} 不需要分解"
            factors = factorint(num)
            parts = []
            for p, e in sorted(factors.items()):
                if e == 1:
                    parts.append(str(p))
                else:
                    parts.append(f"{p}^{e}")
            return f"{n} = {' × '.join(parts)}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def is_prime(n: str) -> str:
        """素性测试(Miller-Rabin)。n为字符串形式的整数"""
        try:
            num = int(n)
            result = sympy_isprime(num)
            return f"{n} {'是' if result else '不是'}素数"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def gcd_lcm(a: str, b: str) -> str:
        """最大公因数和最小公倍数。a,b为字符串形式的整数"""
        try:
            x, y = int(a), int(b)
            g = math.gcd(x, y)
            l = abs(x * y) // g if g != 0 else 0
            return f"GCD({a}, {b}) = {g}\nLCM({a}, {b}) = {l}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def mod_inverse(a: str, m: str) -> str:
        """模逆元。求a关于模m的逆元"""
        try:
            x, mod = int(a), int(m)
            result = pow(x, -1, mod)
            return f"{a}^(-1) mod {m} = {result}"
        except ValueError:
            return f"错误: {a} 关于模 {m} 的逆元不存在 (gcd != 1)"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def mod_pow(base: str, exp: str, mod: str) -> str:
        """模幂运算。计算 base^exp mod mod"""
        try:
            b, e, m = int(base), int(exp), int(mod)
            result = pow(b, e, m)
            return f"{base}^{exp} mod {mod} = {result}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def euler_totient(n: str) -> str:
        """欧拉函数φ(n)"""
        try:
            num = int(n)
            result = totient(num)
            return f"φ({n}) = {result}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def chinese_remainder_theorem(remainders: str, moduli: str) -> str:
        """中国剩余定理。remainders和moduli为逗号分隔的整数列表"""
        try:
            rs = [int(x.strip()) for x in remainders.split(",")]
            ms = [int(x.strip()) for x in moduli.split(",")]
            if len(rs) != len(ms):
                return "错误: remainders和moduli长度必须相同"
            result = crt(ms, rs)
            if result is None:
                return "错误: 无解 (模数不互素)"
            x, mod = result
            eqs = [f"x ≡ {r} (mod {m})" for r, m in zip(rs, ms)]
            return f"方程组:\n" + "\n".join(eqs) + f"\n\n解: x ≡ {x} (mod {mod})"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def extended_gcd(a: str, b: str) -> str:
        """扩展欧几里得算法。返回gcd, x, y使得ax+by=gcd"""
        try:
            x, y, g = gcdex(Integer(int(a)), Integer(int(b)))
            return f"gcd({a}, {b}) = {g}\n{a}*({x}) + {b}*({y}) = {g}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def discrete_log(g: str, h: str, p: str) -> str:
        """离散对数(Baby-step Giant-step)。求x使得g^x ≡ h (mod p)"""
        try:
            gi, hi, pi = int(g), int(h), int(p)
            result = dlog(pi, hi, gi)
            return f"g={g}, h={h}, p={p}\nx = {result} (即 {g}^{result} ≡ {h} mod {p})"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def nth_root_mod(a: str, n: str, p: str) -> str:
        """模n下的开方。求x使得x^n ≡ a (mod p)"""
        try:
            ai, ni, pi = int(a), int(n), int(p)
            results = nthroot_mod(ai, ni, pi, all_roots=True)
            if not results:
                return f"无解: 不存在x使得x^{n} ≡ {a} (mod {p})"
            return f"x^{n} ≡ {a} (mod {p})\n解: {results}"
        except Exception as e:
            return f"错误: {e}"
