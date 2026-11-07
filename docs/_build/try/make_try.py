#!/usr/bin/env python3
"""Compose docs/try.html from the built docs/integrate.html, so it keeps the page's header, footer, type and tokens.

    python3 make_try.py TREE WHEEL

Writes TREE/docs/try.html and TREE/docs/assets/try/<wheel name>. Run it after a page build. Touches nothing else.
"""
import re
import shutil
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
tree, wheel = Path(sys.argv[1]), Path(sys.argv[2])
page = (tree / "docs/integrate.html").read_text()


def sub(pattern: str, new: str, text: str) -> str:
    out, n = re.subn(pattern, lambda _: new, text, count=1, flags=re.S)
    if n != 1:
        raise SystemExit(f"no match for {pattern!r}, nothing written")
    return out


TITLE = "SPILLWAY | try it in your browser"
DESC = "Write a mail and see which addresses SPILLWAY admits. The released package runs in your browser, with no model and no API key."
URL = "https://saintmachines.github.io/spillway/try.html"
page = sub(r"<title>.*?</title>", f"<title>{TITLE}</title>", page)
page = sub(r'<meta name="description" content="[^"]*">', f'<meta name="description" content="{DESC}">', page)
page = sub(r'<link rel="canonical" href="[^"]*">', f'<link rel="canonical" href="{URL}">', page)
page = sub(r'<meta property="og:url" content="[^"]*">', f'<meta property="og:url" content="{URL}">', page)
page = sub(r'<meta property="og:title" content="[^"]*">', f'<meta property="og:title" content="{TITLE}">', page)
page = sub(r'<meta property="og:description" content="[^"]*">', f'<meta property="og:description" content="{DESC}">', page)
page = page.replace(' aria-current="page"', "")
csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', page).group(1)
new_csp = csp.replace("script-src 'self' 'unsafe-inline'", "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net")
new_csp = re.sub(r"connect-src [^;]*", "connect-src 'self' https://cdn.jsdelivr.net", new_csp)
if new_csp == csp or "wasm-unsafe-eval" not in new_csp:
    raise SystemExit("CSP not updated, nothing written")
page = page.replace(csp, new_csp)
page = sub(r"</style>", (here / "try_style.css").read_text() + "</style>", page)
page = sub(r'<main id="main">.*?</main>', (here / "try_main.html").read_text().strip(), page)
page = sub(r"</body>", "<script>\n" + (here / "try_script.js").read_text() + "</script>\n</body>", page)
assets = tree / "docs/assets/try"
assets.mkdir(parents=True, exist_ok=True)
shutil.copy(wheel, assets / wheel.name)
(tree / "docs/try.html").write_text(page)
print("wrote", tree / "docs/try.html", len(page), "bytes,", wheel.name)
