"""Keep this repo to what the blog series needs.

Fails when a tracked file lives outside the allowed top-level paths, is
larger than the size limit, or the total file count grows past the budget.
Raise a limit deliberately, in the same PR that needs it.
"""
import os
import subprocess
import sys

ALLOWED_TOP_LEVEL = {
    ".github", ".gitignore", "LICENSE", "README.md", "SECURITY.md",
    "app", "config", "dashboard", "docs", "examples", "policies",
    "pyproject.toml", "scripts", "start_phase2.sh", "uv.lock",
}
MAX_FILE_KB = {"uv.lock": 600}
DEFAULT_MAX_FILE_KB = 200
MAX_FILES = 160

files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
problems = []
for f in files:
    top = f.split("/", 1)[0]
    if top not in ALLOWED_TOP_LEVEL:
        problems.append(f"outside allowed paths: {f}")
    kb = os.path.getsize(f) / 1024
    limit = MAX_FILE_KB.get(f, DEFAULT_MAX_FILE_KB)
    if kb > limit:
        problems.append(f"too large ({kb:.0f} KB > {limit} KB): {f}")
if len(files) > MAX_FILES:
    problems.append(f"{len(files)} tracked files exceeds budget of {MAX_FILES}")
for p in problems:
    print(p)
print(f"{len(files)} files checked, {len(problems)} problems")
sys.exit(1 if problems else 0)
