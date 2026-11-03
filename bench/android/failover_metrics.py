"""Pure parsers for isolated failover runs; time-to-reply is not an inter-reply gap."""
import re


def ping_window(text, start, end):
    replies = sorted((float(t), int(seq)) for t, seq in re.findall(
        r"^\[([\d.]+)\].*icmp_seq=(\d+)", text, re.M))
    window = [(t, seq) for t, seq in replies if start <= t <= end]
    first = window[0][0] - start if window else None
    # Include the edges so a silent/censored tail cannot appear to be a good run.
    points = [start] + [t for t, _ in window] + [end]
    seqs = {seq for _, seq in window}
    missing = max(seqs) - min(seqs) + 1 - len(seqs) if seqs else None
    return {
        "first_reply_after_s": round(first, 6) if first is not None else None,
        "worst_observed_gap_s": round(max(b - a for a, b in zip(points, points[1:])), 6),
        "window_replies": len(window),
        "missing_between_window_replies": missing,
        "window_s": round(end - start, 6),
        "censored_tail_s": round(end - window[-1][0], 6) if window else round(end - start, 6),
    }
