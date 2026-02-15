import math

from sympy.ntheory import nthroot_mod as sympy_sqrt_mod


def register(mcp):

    def _point_add(x1, y1, x2, y2, a, p):
        """Internal: elliptic curve point addition"""
        if x1 is None:
            return x2, y2
        if x2 is None:
            return x1, y1
        if x1 == x2 and y1 == (-y2 % p):
            return None, None
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None, None
            lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return x3, y3

    def _scalar_mult(k, x, y, a, p):
        """Internal: elliptic curve scalar multiplication (double-and-add)"""
        if k == 0:
            return None, None
        neg = k < 0
        k = abs(k)
        rx, ry = None, None
        qx, qy = x, y
        while k > 0:
            if k & 1:
                rx, ry = _point_add(rx, ry, qx, qy, a, p)
            qx, qy = _point_add(qx, qy, qx, qy, a, p)
            k >>= 1
        if neg and rx is not None:
            ry = (-ry) % p
        return rx, ry

    def _fmt_point(x, y):
        if x is None:
            return "O (无穷远点)"
        return f"({x}, {y})"

    @mcp.tool()
    def ecc_point_add(x1: str, y1: str, x2: str, y2: str, a: str, p: str) -> str:
        """椭圆曲线点加法。曲线 y^2=x^3+ax+b (mod p)。输入十进制。无穷远点用 x1=\"inf\" 表示"""
        try:
            pv = int(p)
            av = int(a)
            if x1.lower() == "inf":
                p1 = (None, None)
            else:
                p1 = (int(x1), int(y1))
            if x2.lower() == "inf":
                p2 = (None, None)
            else:
                p2 = (int(x2), int(y2))

            rx, ry = _point_add(p1[0], p1[1], p2[0], p2[1], av, pv)
            return f"P1 + P2 = {_fmt_point(rx, ry)}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def ecc_scalar_mult(k: str, x: str, y: str, a: str, p: str) -> str:
        """椭圆曲线标量乘法 k*P。曲线 y^2=x^3+ax+b (mod p)。Double-and-add算法"""
        try:
            kv = int(k)
            xp, yp = int(x), int(y)
            av, pv = int(a), int(p)
            rx, ry = _scalar_mult(kv, xp, yp, av, pv)
            return f"{kv} * ({xp}, {yp}) = {_fmt_point(rx, ry)}"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def ecc_find_points(a: str, b: str, p: str, limit: int = 500) -> str:
        """查找椭圆曲线 y^2=x^3+ax+b (mod p) 上的所有点。仅适用于小素数p(<=10000)"""
        try:
            av, bv, pv = int(a), int(b), int(p)
            if pv > 10000:
                return "错误: p太大，仅支持p<=10000"

            points = []
            for x in range(pv):
                rhs = (x * x * x + av * x + bv) % pv
                roots = sympy_sqrt_mod(rhs, 2, pv, all_roots=True)
                if roots:
                    for y in roots:
                        points.append((x, int(y)))

            lines = [f"曲线: y^2 = x^3 + {av}x + {bv} (mod {pv})",
                     f"点数: {len(points) + 1} (含无穷远点O)", ""]

            if len(points) <= limit:
                for pt in points:
                    lines.append(f"  ({pt[0]}, {pt[1]})")
            else:
                for pt in points[:limit]:
                    lines.append(f"  ({pt[0]}, {pt[1]})")
                lines.append(f"  ... (省略 {len(points) - limit} 个点)")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def ecc_point_order(x: str, y: str, a: str, b: str, p: str) -> str:
        """计算椭圆曲线上点P的阶(最小正整数n使得nP=O)"""
        try:
            xp, yp = int(x), int(y)
            av, bv, pv = int(a), int(b), int(p)

            # Hasse bound: |#E - (p+1)| <= 2*sqrt(p)
            max_order = pv + 1 + 2 * int(math.isqrt(pv))

            rx, ry = xp, yp
            for n in range(1, max_order + 1):
                if rx is None:
                    return f"点 ({x}, {y}) 的阶 = {n}"
                rx, ry = _point_add(rx, ry, xp, yp, av, pv)

            return "错误: 超出Hasse界搜索范围"
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def ecc_ecdlp(gx: str, gy: str, px: str, py: str, a: str, p: str, order: str = "") -> str:
        """椭圆曲线离散对数 (ECDLP)。求k使得P=kG。Baby-step Giant-step算法。order: 群阶(可选,加速)"""
        try:
            gxv, gyv = int(gx), int(gy)
            pxv, pyv = int(px), int(py)
            av, pv = int(a), int(p)

            if order:
                n = int(order)
            else:
                n = pv + 1 + 2 * int(math.isqrt(pv))

            m = int(math.isqrt(n)) + 1

            # Baby step: compute j*G for j = 0..m-1
            baby = {}
            rx, ry = None, None
            for j in range(m):
                baby[(rx, ry)] = j
                rx, ry = _point_add(rx, ry, gxv, gyv, av, pv)

            # Giant step: compute P - i*m*G
            mx, my = _scalar_mult(m, gxv, gyv, av, pv)
            neg_mx, neg_my = mx, (-my) % pv if my is not None else (None, None)

            gamma_x, gamma_y = pxv, pyv
            for i in range(m):
                if (gamma_x, gamma_y) in baby:
                    k = i * m + baby[(gamma_x, gamma_y)]
                    return f"ECDLP求解成功!\nk = {k}\n即 P = {k} * G"
                gamma_x, gamma_y = _point_add(gamma_x, gamma_y, neg_mx, neg_my, av, pv)

            return "ECDLP求解失败 (可能需要指定order或搜索空间不够)"
        except Exception as e:
            return f"错误: {e}"
