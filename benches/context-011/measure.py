#!/usr/bin/env python3
"""Measure one child's peak RSS without macOS time(1)'s sandbox-prohibited sysctl.

A fresh wrapper per probe prevents prior children's RSS peaks from contaminating a
later result. The probe still supplies its own operation latency measurements.
"""
import resource
import subprocess
import sys

result = subprocess.run(sys.argv[1:], check=False)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != "darwin":
    rss *= 1024
print(f"{rss} maximum resident set size", file=sys.stderr)
sys.exit(result.returncode)
