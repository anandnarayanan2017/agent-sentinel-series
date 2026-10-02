#!/usr/bin/env bash
# Add one released part of the series to this public repo from the private
# source repo (agent-sentinel-lite, branch series-full-backup).
#
#   scripts/publish_part.sh N          # N = 2..10; creates branch publish-part-NN
#
# It copies Part N's LinkedIn post, technical write-up and image, restores its
# row in docs/blog/README.md and docs/blog/TRACEABILITY.md, re-links earlier
# parts to it, then runs the repo checks and commits. It never pushes: review
# the commit, push the branch and open the PR yourself.
#
# Override the source with SOURCE_REPO and SOURCE_REF if needed.
set -euo pipefail

main() {
N="${1:?usage: scripts/publish_part.sh N   (N = 1..10)}"
[[ "$N" =~ ^([1-9]|10)$ ]] || { echo "N must be 1..10" >&2; exit 2; }
NN=$(printf '%02d' "$N")
SOURCE_REPO="${SOURCE_REPO:-https://github.com/anandnarayanan2017/agent-sentinel-lite}"
SOURCE_REF="${SOURCE_REF:-series-full-backup}"

cd "$(git rev-parse --show-toplevel)"
[[ -z "$(git status --porcelain)" ]] || { echo "working tree not clean" >&2; exit 1; }

git fetch -q origin main
git checkout -q -B "publish-part-$NN" origin/main
git fetch -q "$SOURCE_REPO" "$SOURCE_REF"
SRC=FETCH_HEAD

python3 - "$N" "$SRC" <<'PY'
import glob, os, re, subprocess, sys

n, src = int(sys.argv[1]), sys.argv[2]
B = "docs/blog"

def show(path):
    return subprocess.run(["git", "show", f"{src}:{path}"], check=True,
                          capture_output=True).stdout

def ls(prefix):
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", src, prefix],
                         check=True, capture_output=True, text=True).stdout
    return out.split()

def num(path):
    m = re.match(r"(\d+)-", os.path.basename(path))
    return int(m.group(1)) if m else None

# 1. Copy parts 1..n (posts, write-ups, images) from the source. Re-copying
#    earlier parts restores any link that pointed at a part now released.
new = False
for d in ("linkedin", "technical-details", "images"):
    for p in ls(f"{B}/{d}/"):
        k = num(p)
        if k is None or k > n:
            continue
        if k == n and not os.path.exists(p):
            new = True
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(show(p))
if not new:
    sys.exit(f"Part {n} not found in source, or already published")

# 2. Unlink references to parts that are not published yet (> n).
for p in glob.glob(f"{B}/technical-details/*.md") + glob.glob(f"{B}/linkedin/*.md"):
    t = open(p, encoding="utf-8").read()
    t2 = re.sub(r"\[([^\]]+)\]\((?:\.\./(?:technical-details|linkedin)/|)"
                r"(0[1-9]|10)-[^)]*\)",
                lambda m: m.group(0) if int(m.group(2)) <= n else m.group(1), t)
    if t2 != t:
        open(p, "w", encoding="utf-8").write(t2)

# 3. README table row: replace the "coming soon" row with the source row.
src_readme = show(f"{B}/README.md").decode().split("\n")
row = next(l for l in src_readme if re.match(rf"\| {n} \|", l) and "linkedin/" in l)
p = f"{B}/README.md"
lines = open(p, encoding="utf-8").read().split("\n")
lines = [row if re.match(rf"\| {n} \| .*coming soon", l) else l for l in lines]
open(p, "w", encoding="utf-8").write("\n".join(lines))

# 4. TRACEABILITY row, inserted in numeric order.
src_tr = show(f"{B}/TRACEABILITY.md").decode().split("\n")
trow = next(l for l in src_tr if re.match(rf"\| {n} \|", l))
p = f"{B}/TRACEABILITY.md"
lines = open(p, encoding="utf-8").read().split("\n")
idx = max(i for i, l in enumerate(lines)
          if (m := re.match(r"\| (\d+) \|", l)) and int(m.group(1)) < n)
lines.insert(idx + 1, trow)
open(p, "w", encoding="utf-8").write("\n".join(lines))
PY

python3 scripts/check_links.py
python3 scripts/check_scope.py
python3 -m pytest -q -m "not integration"

git add -A
git commit -q -m "Publish Part $N of the Agent Sentinel series"
echo
echo "Committed on branch publish-part-$NN. Review with 'git show --stat', then:"
echo "  git push -u origin publish-part-$NN   # and open a PR into main"
}

# Everything lives in main() so bash has read the whole script before it
# switches branches (which can replace this file on disk).
main "$@"
exit
