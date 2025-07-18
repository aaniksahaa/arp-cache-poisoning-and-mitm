# file: inject_body.py
from mitmproxy import http
import re

BODY_INJECT = "<h1>Hello Bro!</h1>"

def response(flow: http.HTTPFlow) -> None:
    # only HTML
    ct = flow.response.headers.get("Content-Type", "")
    if "text/html" not in ct.lower():
        return

    html = flow.response.get_text()  # auto‑decodes gzip/deflate
    # insert after <body> or at start
    m = re.search(r"(?i)<body[^>]*>", html)
    if m:
        idx = m.end()
        html = html[:idx] + BODY_INJECT + html[idx:]
    else:
        html = BODY_INJECT + html

    flow.response.set_text(html)    # auto‑re‑encodes with original headers
