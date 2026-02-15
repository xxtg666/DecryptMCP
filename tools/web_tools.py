import json
import re
import base64
import datetime

import httpx


def register(mcp):

    @mcp.tool()
    def web_search(query: str, max_results: int = 5) -> str:
        """网络搜索(DuckDuckGo)。返回搜索结果摘要"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            resp = httpx.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers=headers,
                timeout=10,
                follow_redirects=True,
            )
            results = re.findall(
                r'<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)</a>.*?'
                r'<a class="result__snippet"[^>]*>(.*?)</a>',
                resp.text, re.DOTALL
            )
            if not results:
                results_alt = re.findall(
                    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                    resp.text, re.DOTALL
                )
                lines = [f"搜索: {query}", ""]
                for url, title in results_alt[:max_results]:
                    clean_title = re.sub(r'<[^>]+>', '', title).strip()
                    lines.append(f"- {clean_title}\n  {url}")
                return "\n".join(lines) if len(lines) > 2 else "未找到结果"

            lines = [f"搜索: {query}", ""]
            for url, title, snippet in results[:max_results]:
                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                clean_snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                lines.append(f"- {clean_title}\n  {url}\n  {clean_snippet}")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def http_request(url: str, method: str = "GET", headers_json: str = "{}", body: str = "") -> str:
        """HTTP请求。method: GET/POST/PUT/DELETE。headers_json: JSON格式请求头"""
        try:
            hdrs = json.loads(headers_json) if headers_json else {}
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                if method.upper() == "GET":
                    resp = client.get(url, headers=hdrs)
                elif method.upper() == "POST":
                    resp = client.post(url, headers=hdrs, content=body)
                elif method.upper() == "PUT":
                    resp = client.put(url, headers=hdrs, content=body)
                elif method.upper() == "DELETE":
                    resp = client.delete(url, headers=hdrs)
                else:
                    return f"错误: 不支持的方法 {method}"

            lines = [
                f"状态码: {resp.status_code}",
                f"响应头:",
            ]
            for k, v in resp.headers.items():
                lines.append(f"  {k}: {v}")
            lines.append(f"\n响应体 (前2000字符):")
            lines.append(resp.text[:2000])
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def dns_lookup(domain: str, record_type: str = "A") -> str:
        """DNS查询。record_type: A/AAAA/MX/NS/TXT/CNAME/SOA"""
        try:
            resp = httpx.get(
                f"https://dns.google/resolve",
                params={"name": domain, "type": record_type},
                timeout=10,
            )
            data = resp.json()
            lines = [f"DNS查询: {domain} (类型: {record_type})", ""]
            if "Answer" in data:
                for answer in data["Answer"]:
                    lines.append(f"  {answer.get('name', '')} -> {answer.get('data', '')} (TTL: {answer.get('TTL', '')})")
            else:
                lines.append("  未找到记录")
            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def jwt_decode(token: str) -> str:
        """JWT令牌解码分析。解码header和payload(不验证签名)"""
        try:
            parts = token.strip().split('.')
            if len(parts) != 3:
                return "错误: 无效的JWT格式(需要3个部分用.分隔)"

            def decode_part(part):
                padding = (4 - len(part) % 4) % 4
                padded = part + '=' * padding
                decoded = base64.urlsafe_b64decode(padded)
                return json.loads(decoded)

            header = decode_part(parts[0])
            payload = decode_part(parts[1])

            lines = [
                "=== JWT Header ===",
                json.dumps(header, indent=2, ensure_ascii=False),
                "",
                "=== JWT Payload ===",
                json.dumps(payload, indent=2, ensure_ascii=False),
                "",
                f"=== Signature (hex) ===",
            ]
            try:
                padding = (4 - len(parts[2]) % 4) % 4
                sig = base64.urlsafe_b64decode(parts[2] + '=' * padding)
                lines.append(sig.hex())
            except Exception:
                lines.append(parts[2])

            if 'exp' in payload:
                exp_time = datetime.datetime.fromtimestamp(payload['exp'])
                lines.append(f"\n过期时间: {exp_time.isoformat()}")
            if 'iat' in payload:
                iat_time = datetime.datetime.fromtimestamp(payload['iat'])
                lines.append(f"签发时间: {iat_time.isoformat()}")

            return "\n".join(lines)
        except Exception as e:
            return f"错误: {e}"
