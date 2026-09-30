"""Fail if any relative Markdown link or heading anchor in the repo is broken."""
import glob
import os
import re
import sys


def slug(h):
    return re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")


def anchors(path):
    text = open(path, encoding="utf-8").read()
    found = {slug(m.group(1)) for m in re.finditer(r"^#+\s+(.*)$", text, re.M)}
    return found | set(re.findall(r'<a id="([^"]+)"', text))


bad = []
for f in glob.glob("**/*.md", recursive=True):
    text = re.sub(r"```.*?```", "", open(f, encoding="utf-8").read(), flags=re.S)
    for m in re.finditer(r"\]\(([^)\s]+)\)", text):
        url = m.group(1)
        if url.startswith(("http", "mailto")):
            continue
        path, _, frag = url.partition("#")
        target = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
        if not os.path.exists(target):
            bad.append((f, url))
        elif frag and target.endswith(".md") and frag not in anchors(target):
            bad.append((f, url))
for f, u in bad:
    print(f"BROKEN {f}: {u}")
sys.exit(1 if bad else 0)
