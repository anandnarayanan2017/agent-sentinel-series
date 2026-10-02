#!/usr/bin/env bash
# Add one released part of the series to this public repo from the private
# source repo (agent-sentinel-lite, branch series-full-backup).
#
#   scripts/publish_part.sh N          # N = 2..10; creates branch publish-part-NN
#   scripts/publish_part.sh A-B        # a range, e.g. 2-5; one branch, one commit
#
# It copies Part N's LinkedIn post, technical write-up and image, restores its
# row in docs/blog/README.md and docs/blog/TRACEABILITY.md, re-links earlier
# parts to it (touching nothing else in them), and for Part 6 restores the
# network-collector code that Parts 1-5 do not include. It then runs the repo
# checks (tests, links, scope, end-to-end) and commits. It never pushes: review
# the commit, push the branch and open the PR yourself.
#
# Override the source with SOURCE_REPO and SOURCE_REF if needed.
# The source branch must also hold patches/restore-code-parts-6-10.patch.
set -euo pipefail

main() {
ARG="${1:?usage: scripts/publish_part.sh N | A-B   (parts 1..10)}"
[[ "$ARG" =~ ^([1-9]|10)(-([1-9]|10))?$ ]] || { echo "argument must be N or A-B, parts 1..10" >&2; exit 2; }
FIRST="${ARG%-*}"; LAST="${ARG#*-}"
(( FIRST <= LAST )) || { echo "range is backwards" >&2; exit 2; }
BRANCH="publish-part-$(printf '%02d' "$FIRST")"
[[ "$FIRST" == "$LAST" ]] || BRANCH="publish-parts-$(printf '%02d' "$FIRST")-$(printf '%02d' "$LAST")"
SOURCE_REPO="${SOURCE_REPO:-https://github.com/anandnarayanan2017/agent-sentinel-lite}"
SOURCE_REF="${SOURCE_REF:-series-full-backup}"

cd "$(git rev-parse --show-toplevel)"
[[ -z "$(git status --porcelain)" ]] || { echo "working tree not clean" >&2; exit 1; }

BASE_REF="${BASE_REF:-origin/main}"   # override only to test against an unpushed branch
[[ "$BASE_REF" != origin/main ]] || git fetch -q origin main
git checkout -q -B "$BRANCH" "$BASE_REF"
git fetch -q "$SOURCE_REPO" "$SOURCE_REF"
SRC=FETCH_HEAD

for N in $(seq "$FIRST" "$LAST"); do
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

# 1. Copy Part n's own files (post, write-up, image) from the source. Earlier
#    parts are never overwritten: this repository is the source of truth for
#    anything already published.
new = False
for d in ("linkedin", "technical-details", "images"):
    for p in ls(f"{B}/{d}/"):
        if num(p) != n:
            continue
        if not os.path.exists(p):
            new = True
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(show(p))
if not new:
    sys.exit(f"Part {n} not found in source, or already published")

LINK = r"\[([^\]]+)\]\(((?:\.\./(?:technical-details|linkedin)/|)(0[1-9]|10)-[^)]*)\)"
mine = [p for d in ("linkedin", "technical-details") for p in glob.glob(f"{B}/{d}/{n:02d}-*.md")]

# 2a. In the new part, leave references to parts not yet published as plain text.
for p in mine:
    t = open(p, encoding="utf-8").read()
    t2 = re.sub(LINK, lambda m: m.group(0) if int(m.group(3)) <= n else m.group(1), t)
    if t2 != t:
        open(p, "w", encoding="utf-8").write(t2)

# 2b. In earlier parts, turn plain-text mentions of Part n into links, using the
#     link target the source uses for that label. Nothing else in them changes.
for d in ("linkedin", "technical-details"):
    for p in glob.glob(f"{B}/{d}/*.md"):
        if num(p) is None or num(p) >= n:
            continue
        t = open(p, encoding="utf-8").read()
        try:
            source = show(p).decode()
        except subprocess.CalledProcessError:
            continue
        for m in re.finditer(LINK, source):
            if int(m.group(3)) != n:
                continue
            label, url = m.group(1), m.group(2)
            t = re.sub(r"(?<!\[)" + re.escape(label) + r"(?!\])", lambda _: f"[{label}]({url})", t, count=1)
        open(p, "w", encoding="utf-8").write(t)

# 2c. Part 6 is where the network-visibility collector appears: bring back the
#     code, tests, config and docs that were held back (kept in the source repo
#     as patches/restore-code-parts-6-10.patch).
if n == 6 and not os.path.exists("app/sentinel/collector/network_scan.py"):
    patch = show("patches/restore-code-parts-6-10.patch")
    subprocess.run(["git", "apply", "--3way", "-"], input=patch, check=True)

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
done

python3 scripts/check_links.py
python3 scripts/check_scope.py
python3 -m pytest -q -m "not integration"
python3 scripts/e2e.py

git add -A
git commit -q -m "Publish Part${LAST:+s} $ARG of the Agent Sentinel series"
echo
echo "Committed on branch $BRANCH. Review with 'git show --stat', then:"
echo "  git push -u origin $BRANCH   # and open a PR into main"
}

# Everything lives in main() so bash has read the whole script before it
# switches branches (which can replace this file on disk).
main "$@"
exit
