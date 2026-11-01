"""Compare scoring models v1 and v2 side by side. Writes nothing.

Usage: python scripts/compare_models.py
"""
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scoring"))
sys.path.insert(0, os.path.join(ROOT, "feeds"))
import run_scoring  # noqa: E402  (reuses its facts query and both models)


def ranks(values):
    """Average rank of each value; ties share a rank."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            out[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return out


def spearman(a, b):
    ra, rb = ranks(a), ranks(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra) ** 0.5
    vb = sum((x - mb) ** 2 for x in rb) ** 0.5
    return cov / (va * vb) if va and vb else float("nan")


def main():
    conn = run_scoring._conn()
    facts_list = run_scoring.load_facts(conn)
    conn.close()
    now = datetime.now(timezone.utc)
    m1, m2 = run_scoring.MODELS["v1"], run_scoring.MODELS["v2"]
    rows = [(f, m1.score_indicator(f, now)["score"], m2.score_indicator(f, now)["score"])
            for f in facts_list]

    print("== by indicator type: count, then min/avg/max for each model")
    by_type = defaultdict(list)
    for f, s1, s2 in rows:
        by_type[f["indicator_type"]].append((s1, s2))
    for t, pairs in sorted(by_type.items()):
        a, b = [p[0] for p in pairs], [p[1] for p in pairs]
        print(f"{t:12} n={len(pairs):5}  v1 {min(a):3}/{sum(a)/len(a):5.1f}/{max(a):3}"
              f"   v2 {min(b):3}/{sum(b)/len(b):5.1f}/{max(b):3}")

    print("\n== average score by source (indicators listed by that one source only)")
    by_src = defaultdict(list)
    for f, s1, s2 in rows:
        srcs = list((f.get("source_conf") or {}).keys())
        if len(srcs) == 1:
            by_src[srcs[0]].append((s1, s2))
    for s, pairs in sorted(by_src.items()):
        print(f"{s:10} n={len(pairs):5}  v1 {sum(p[0] for p in pairs)/len(pairs):5.1f}"
              f"   v2 {sum(p[1] for p in pairs)/len(pairs):5.1f}")

    ips = [r for r in rows if r[0]["indicator_type"] == "IP"]
    if len(ips) > 2:
        corr = spearman([r[1] for r in ips], [r[2] for r in ips])
        print(f"\n== IPs: rank agreement v1 vs v2 (Spearman) = {corr:.2f}   (1.00 = identical order)")
        r1, r2 = ranks([-r[1] for r in ips]), ranks([-r[2] for r in ips])   # rank 1 = highest score
        print("== IPs whose position changed most")
        for i in sorted(range(len(ips)), key=lambda i: abs(r1[i] - r2[i]), reverse=True)[:8]:
            f = ips[i][0]
            vt = f.get("vt") or {}
            print(f"{f['value']:16} v1 rank {r1[i]:5.0f} score {ips[i][1]:3} | v2 rank {r2[i]:5.0f} "
                  f"score {ips[i][2]:3} | {','.join(f['source_conf'] or {})} | VT engines {vt.get('malicious', '-')}")


if __name__ == "__main__":
    main()
