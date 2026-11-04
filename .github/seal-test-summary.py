#!/usr/bin/env python3
# Summarise Ant plain-formatter JUnit logs (output/build/logs/TEST-*.txt):
# prints per-suite failures, every skipped test with its reason, grouped skip
# reasons and a TOTAL line, so the passing-test count is visible in the CI log.
import glob
import os
import re
import sys
from collections import Counter

LOG_DIR = sys.argv[1] if len(sys.argv) > 1 else "output/build/logs"
HEADER = re.compile(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")
TESTCASE = re.compile(r"^Testcase: (\S+)")


def annotate(suite, case, msg):
    """Explain bare/opaque assumption messages by naming the real cause."""
    hint = ""
    if re.search(r"FFM|panama", suite + case, re.I):
        hint = "OpenSSL FFM (panama) variant: needs JRE 22+ with OpenSSL FFM available"
    src = os.path.join("test", suite.replace(".", "/") + ".java")
    method = re.split(r"[\[\s(]", case)[0]
    assume = ""
    if os.path.exists(src):
        with open(src, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = None
        for i, line in enumerate(lines):
            if re.search(r"\b" + re.escape(method) + r"\s*\(", line):
                start = i
                break
        scan = lines[start:start + 40] if start is not None else lines
        for line in scan:
            if re.search(r"Assume\.|assume(True|False|That|NotNull|NoException)\(", line) and "import" not in line:
                assume = line.strip()
                break
        if not assume:
            for line in lines:
                if ("Assume." in line or "@Ignore" in line) and "import" not in line:
                    assume = line.strip()
                    break
    parts = [msg or "(no message)"]
    if hint:
        parts.append(hint)
    if assume:
        parts.append("source: " + assume)
    return " -- ".join(parts)


tot = Counter()
skips = []
groups = Counter()
failed_suites = []
for path in sorted(glob.glob(os.path.join(LOG_DIR, "TEST-*.txt"))):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    suite_file = os.path.basename(path)[5:-4]
    suite = re.sub(r"\.(NIO2?|APR)$", "", suite_file)
    header = None
    for line in lines:
        m = HEADER.search(line)
        if m:
            header = tuple(int(x) for x in m.groups())
            break
    cases = 0
    fails = 0
    nskip = 0
    current = None
    for line in lines:
        m = TESTCASE.match(line)
        if m:
            cases += 1
            current = m.group(1)
            continue
        s = line.strip()
        if s.startswith("FAILED") or s.startswith("Caused an ERROR"):
            fails += 1
        if s.startswith("SKIPPED"):
            nskip += 1
            msg = s[len("SKIPPED"):].lstrip(": ").strip()
            reason = annotate(suite, current or "?", msg)
            skips.append("SKIPPED %s#%s: %s" % (suite_file, current, reason))
            groups["%s -- %s" % (suite, reason)] += 1
    if header:
        run, f_, e_, sk = header
    else:
        run, f_, e_, sk = cases, fails, 0, nskip
        print("NOTE %s has no 'Tests run' header; counted %d testcases from the log" % (suite_file, cases))
    tot["suites"] += 1
    tot["run"] += run
    tot["fail"] += f_
    tot["err"] += e_
    tot["skip"] += sk
    if f_ or e_:
        failed_suites.append("%s (failures=%d errors=%d)" % (suite_file, f_, e_))

for s in skips:
    print(s)
for k, v in sorted(groups.items()):
    print("SKIP-GROUP %d x %s" % (v, k))
for s in failed_suites:
    print("FAILED-SUITE " + s)
passed = tot["run"] - tot["fail"] - tot["err"] - tot["skip"]
print("TOTAL: suites=%d tests_run=%d passed=%d failures=%d errors=%d skipped=%d"
      % (tot["suites"], tot["run"], passed, tot["fail"], tot["err"], tot["skip"]))
