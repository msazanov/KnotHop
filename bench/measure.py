"""Measurements shared by the stack-comparison harnesses (lev_cell.py, protocol_compare.py).

Kept in one place so every stack is read the same way: process RSS from /proc,
percentiles with one definition.
"""
import re

# Names as the kernel reports them in /proc/<pid>/status (15 chars max).
TRACKED = ("rns-iroh-node", "tcp-load", "xray", "amneziawg-go", "openssl")


def process_memory(run):
    """VmHWM (peak) and VmRSS (now), KiB, of the tracked processes in one container.

    `run(*argv)` executes argv inside the container and returns stdout. A process
    that already exited is not visible here; callers add its self-reported figures.
    """
    out = run("sh", "-c", "grep -H -E '^(Name|VmHWM|VmRSS):' /proc/[0-9]*/status 2>/dev/null || true")
    procs = {}
    for line in out.splitlines():
        m = re.match(r"/proc/(\d+)/status:(\w+):\s+(\S+)", line)
        if m:
            pid, key, value = m.groups()
            procs.setdefault(pid, {})[key] = value
    rows = []
    for pid, fields in procs.items():
        if fields.get("Name") in TRACKED:
            rows.append({"pid": int(pid), "name": fields["Name"],
                         "hwm_kb": int(fields.get("VmHWM", 0)), "rss_kb": int(fields.get("VmRSS", 0))})
    return sorted(rows, key=lambda r: r["pid"])


def percentile(sorted_samples, p):
    """Nearest-rank percentile of an already sorted list."""
    if not sorted_samples:
        return None
    rank = (len(sorted_samples) * p + 99) // 100
    return sorted_samples[max(0, min(len(sorted_samples) - 1, rank - 1))]


def rtt_summary(samples, timeouts=0):
    ordered = sorted(samples)
    return {"samples": len(ordered), "timeouts": timeouts,
            **{f"p{p}_ms": percentile(ordered, p) for p in (50, 95, 99)}}
