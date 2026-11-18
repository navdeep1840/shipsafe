"""Rebuild data/sample.csv from the Tranco list used in this study.

Tranco list V38GN (https://tranco-list.eu/list/V38GN), downloaded 2026-11-18.
We don't redistribute the list; download it yourself:
    curl -L -o data/top-1m.csv https://tranco-list.eu/download/V38GN/1000000
then run:  python3 make-sample.py
"""
import csv, random

rows = [r[1] for r in csv.reader(open("data/top-1m.csv"))]
random.seed(42)
tiers = {"top": rows[:150], "mid": random.sample(rows[1000:100000], 150), "long": random.sample(rows[100000:], 150)}
with open("data/sample.csv", "w") as f:
    f.write("tier,domain\n")
    for t, ds in tiers.items():
        for d in ds:
            f.write(f"{t},{d}\n")
