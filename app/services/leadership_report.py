"""
Leadership one-pager: the numbers a non-technical reader needs, on one page.

The Reports page answers analyst questions (who holds what, which tactics recur).
This answers the ones leadership asks: how many incidents, how fast we contain
and close them, what is still open and how long it has been open. Everything
here is computed from the case record itself; nothing is estimated or filled in.

Definitions, stated once so the page and the code cannot drift apart:

- Opened in period: opened_date falls inside the reporting window.
- Closed in period: status is Closed and closed_date falls inside the window.
- Days to contain: contained_date minus opened_date, for cases contained in the
  window. Days to close: closed_date minus opened_date, for cases closed in it.
- "Typical" is the median, not the mean. One case left open over a holiday
  should not move the headline the way it moves an average.
- A case missing a date it would need, or carrying a date earlier than its
  opened_date, is left out of that figure and counted in data_gaps, so the page
  can say how many cases a number rests on.
"""

from collections import Counter
from datetime import datetime, timedelta
from statistics import median

from flask import current_app

from ..models import Case

# Reporting windows, in the order the page offers them: (key, button label).
# 30 days is a rolling window bucketed by week; the others are calendar months
# bucketed by month, the current month included.
PERIODS = (
    ("30d", "30 days"),
    ("3m", "3 months"),
    ("6m", "6 months"),
    ("12m", "12 months"),
)
PERIOD_KEYS = tuple(k for k, _ in PERIODS)
DEFAULT_PERIOD = "12m"

# Open-case aging buckets, in days since opened: (label, low inclusive, high inclusive).
AGING_BUCKETS = (
    ("0 to 7 days", 0, 7),
    ("8 to 30 days", 8, 30),
    ("31 to 90 days", 31, 90),
    ("Over 90 days", 91, None),
)

TOP_TYPES = 5
OLDEST_OPEN = 5


def _month_start(dt: datetime) -> datetime:
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt: datetime, n: int) -> datetime:
    y, m = divmod(dt.month - 1 + n, 12)
    return dt.replace(year=dt.year + y, month=m + 1)


def _days(start, end):
    """Elapsed days as a float, or None when either date is missing or inverted."""
    if start is None or end is None or end < start:
        return None
    return (end - start).total_seconds() / 86400


def _typical(values):
    return round(median(values), 1) if values else None


def _day_start(dt: datetime) -> datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _span_label(start: datetime, last_day: datetime) -> str:
    """'Oct 7–13', or 'Oct 29–Nov 4' across a month boundary, or 'Nov 5' for one day."""
    if start.date() == last_day.date():
        return f"{start:%b} {start.day}"
    if start.month == last_day.month:
        return f"{start:%b} {start.day}\u2013{last_day.day}"
    return f"{start:%b} {start.day}\u2013{last_day:%b} {last_day.day}"


def _buckets(now: datetime, period: str):
    """
    The window and its chart buckets: (window_start, window_end, unit, buckets),
    each bucket a dict with start, end (exclusive), label and full_label.
    """
    if period == "30d":
        # Thirty calendar days, today included, in weeks counted back from today
        # so the most recent week is always whole. The oldest bucket holds the
        # two days left over, and its label says so.
        window_end = _day_start(now) + timedelta(days=1)
        window_start = window_end - timedelta(days=30)
        edges = [window_start]
        edge = window_start + timedelta(days=30 % 7 or 7)
        while edge < window_end:
            edges.append(edge)
            edge += timedelta(days=7)
        edges.append(window_end)
        buckets = []
        for a, b in zip(edges, edges[1:]):
            last = b - timedelta(days=1)
            label = _span_label(a, last)
            buckets.append({"start": a, "end": b, "label": label,
                            "full_label": f"{a:%B} {a.day} to {last:%B} {last.day}"
                            if a.date() != last.date() else f"{a:%B} {a.day}"})
        return window_start, window_end, "week", buckets

    months = int(period[:-1])
    first = _add_months(_month_start(now), -(months - 1))
    buckets = []
    for i in range(months):
        a, b = _add_months(first, i), _add_months(first, i + 1)
        label = f"{a:%b}" if i and a.month != 1 else f"{a:%b} {a:%y}"
        buckets.append({"start": a, "end": b, "label": label, "full_label": f"{a:%B %Y}"})
    return first, buckets[-1]["end"], "month", buckets


def build(now: datetime, period=DEFAULT_PERIOD) -> dict:
    """
    Compute every figure on the leadership one-pager for the window ending *now*.

    *period* is a key from PERIODS. A bare integer is read as that many months,
    which keeps ?months=6 links working; anything unrecognized falls back to 12.
    """
    if isinstance(period, int):
        period = f"{period}m"
    if period not in PERIOD_KEYS:
        period = DEFAULT_PERIOD

    window_start, window_end, unit, buckets = _buckets(now, period)

    def in_window(dt):
        return dt is not None and window_start <= dt < window_end

    def in_bucket(dt, b):
        return dt is not None and b["start"] <= dt < b["end"]

    cases = Case.query.all()

    opened = [c for c in cases if in_window(c.opened_date)]
    closed = [c for c in cases if c.status == "Closed" and in_window(c.closed_date)]
    contained = [c for c in cases if in_window(c.contained_date)]
    open_now = [c for c in cases if c.status != "Closed"]

    close_days = [d for d in (_days(c.opened_date, c.closed_date) for c in closed) if d is not None]
    contain_days = [d for d in (_days(c.opened_date, c.contained_date) for c in contained)
                    if d is not None]

    # ── Per bucket (month, or week in the 30-day view) ───────────────────────
    series = []
    for b in buckets:
        b_close = [d for c in closed if in_bucket(c.closed_date, b)
                   for d in [_days(c.opened_date, c.closed_date)] if d is not None]
        series.append({
            "label": b["label"],
            "full_label": b["full_label"],
            "opened": sum(1 for c in opened if in_bucket(c.opened_date, b)),
            "closed": sum(1 for c in closed if in_bucket(c.closed_date, b)),
            "typical_close_days": _typical(b_close),
        })

    # ── By severity ──────────────────────────────────────────────────────────
    severities = list(current_app.config["CASE_SEVERITIES"])
    by_severity = []
    for sev in severities:
        s_close = [d for c in closed if c.severity == sev
                   for d in [_days(c.opened_date, c.closed_date)] if d is not None]
        s_contain = [d for c in contained if c.severity == sev
                     for d in [_days(c.opened_date, c.contained_date)] if d is not None]
        row = {
            "severity": sev,
            "opened": sum(1 for c in opened if c.severity == sev),
            "closed": sum(1 for c in closed if c.severity == sev),
            "open_now": sum(1 for c in open_now if c.severity == sev),
            "typical_contain_days": _typical(s_contain),
            "typical_close_days": _typical(s_close),
        }
        by_severity.append(row)
    # A row of zeros says nothing to this reader; keep only severities in play.
    by_severity = [r for r in by_severity if r["opened"] or r["closed"] or r["open_now"]]

    # ── Open cases: how long they have been open ─────────────────────────────
    aging = []
    for label, lo, hi in AGING_BUCKETS:
        n = 0
        for c in open_now:
            if c.opened_date is None:
                continue
            age = (now - c.opened_date).days
            if age >= lo and (hi is None or age <= hi):
                n += 1
        aging.append({"label": label, "count": n})

    oldest_open = sorted(
        (c for c in open_now if c.opened_date is not None),
        key=lambda c: c.opened_date,
    )[:OLDEST_OPEN]
    oldest_open = [{
        "id": c.id, "case_id": c.case_id, "title": c.title, "severity": c.severity,
        "status": c.status, "days_open": (now - c.opened_date).days,
    } for c in oldest_open]

    # ── What kind of incidents ───────────────────────────────────────────────
    type_counts = Counter((c.case_type or "Unclassified") for c in opened)
    top_types = type_counts.most_common(TOP_TYPES)
    other = sum(type_counts.values()) - sum(n for _, n in top_types)
    if other:
        top_types.append(("All other types", other))

    # ── How much of the record the time figures rest on ─────────────────────
    closed_status_no_date = sum(1 for c in cases if c.status == "Closed" and c.closed_date is None)
    inverted = sum(
        1 for c in cases
        if (c.closed_date and c.opened_date and c.closed_date < c.opened_date)
        or (c.contained_date and c.opened_date and c.contained_date < c.opened_date)
    )

    return {
        "period": period,
        "period_name": dict(PERIODS)[period],
        "periods": PERIODS,
        "unit": unit,
        "period_start": window_start,
        "period_end": now,
        "generated_at": now,
        "kpis": {
            "opened": len(opened),
            "closed": len(closed),
            "open_now": len(open_now),
            "critical_high_opened": sum(1 for c in opened if c.severity in ("Critical", "High")),
            "typical_contain_days": _typical(contain_days),
            "contain_sample": len(contain_days),
            "contained_total": len(contained),
            "typical_close_days": _typical(close_days),
            "close_sample": len(close_days),
            "escalated": sum(1 for c in opened if c.escalated),
            "board_flagged": sum(1 for c in opened if c.board_flagged),
        },
        "series": series,
        "chart": series_chart_svg(series, unit),
        "by_severity": by_severity,
        "aging": aging,
        "oldest_open": oldest_open,
        "top_types": top_types,
        "data_gaps": {
            "closed_without_date": closed_status_no_date,
            "dates_out_of_order": inverted,
        },
    }


# ---------------------------------------------------------------------------
# Chart: cases opened and closed per month
# ---------------------------------------------------------------------------
#
# Drawn server-side as inline SVG. It prints exactly as it shows, needs no
# script (the CSP still carries 'unsafe-inline', but a chart has no business
# depending on that), and works in the PDF a leader is most likely to read.
# Colors are the first two slots of the validated default categorical palette;
# identity is never color alone, since the legend names both and the table
# under the chart carries every value.

OPENED_COLOR = "#2a78d6"
CLOSED_COLOR = "#eb6834"


def _nice_max(v: int, ticks: int = 4) -> int:
    """Smallest axis top above *v* that splits into *ticks* whole-number steps.
    Cases are counted in whole numbers; a gridline at 2.5 cases means nothing."""
    for step in (1, 2, 3, 4, 5, 10, 15, 20, 25, 50, 100, 250, 500, 1000):
        if v <= step * ticks:
            return step * ticks
    return -(-v // ticks) * ticks


def _bar(x, y_top, w, base_y, r=2):
    """A bar with rounded data-end (top) corners, square at the baseline."""
    h = base_y - y_top
    if h <= 0:
        return ""
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{base_y:.1f} V{y_top + r:.1f} "
            f"Q{x:.1f},{y_top:.1f} {x + r:.1f},{y_top:.1f} "
            f"H{x + w - r:.1f} Q{x + w:.1f},{y_top:.1f} {x + w:.1f},{y_top + r:.1f} "
            f"V{base_y:.1f} Z")


def series_chart_svg(series, unit="month", width=720, height=210) -> str:
    """
    Grouped bars, opened beside closed, with the values set as rows of text
    under each month (or week). The rows sit in the same SVG as the bars so every number
    lines up under its own month; a separate HTML table could not guarantee it.
    """
    row_h = 13
    left, right, top, bottom = 108, 8, 8, 18 + row_h * 3 + 6
    plot_w = width - left - right
    plot_h = height - top - bottom
    base_y = top + plot_h
    peak = max([m["opened"] for m in series] + [m["closed"] for m in series] + [0])
    y_max = _nice_max(peak)
    ticks = 4

    def y(v):
        return base_y - (v / y_max) * plot_h

    n = len(series)
    group_w = plot_w / n
    bar_w = min(18.0, (group_w - 10) / 2)
    gap = 2

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
        f'aria-label="Cases opened and closed per {unit}" '
        f'xmlns="http://www.w3.org/2000/svg" font-family="inherit">'
    ]
    for t in range(ticks + 1):
        v = y_max * t / ticks
        yy = y(v)
        stroke = "#c9c8c3" if t == 0 else "#ebeae6"
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{yy:.1f}" y2="{yy:.1f}" '
                     f'stroke="{stroke}" stroke-width="1"/>')
        label = f"{v:g}" if v == int(v) else f"{v:.1f}"
        parts.append(f'<text x="{left - 6}" y="{yy + 3:.1f}" text-anchor="end" '
                     f'font-size="9" fill="#52514e">{label}</text>')

    for i, m in enumerate(series):
        cx = left + group_w * i + group_w / 2
        x_open = cx - gap / 2 - bar_w
        x_close = cx + gap / 2
        for x0, val, color, word in ((x_open, m["opened"], OPENED_COLOR, "opened"),
                                     (x_close, m["closed"], CLOSED_COLOR, "closed")):
            d = _bar(x0, y(val), bar_w, base_y)
            tip = f"{m['full_label']}: {val} {word}"
            if d:
                parts.append(f'<path d="{d}" fill="{color}"><title>{tip}</title></path>')
            # A hit target taller than the mark, so a zero or a short bar still
            # answers a hover.
            parts.append(f'<rect x="{x0:.1f}" y="{top}" width="{bar_w:.1f}" height="{plot_h}" '
                         f'fill="transparent"><title>{tip}</title></rect>')
        label = m["label"]
        parts.append(f'<text x="{cx:.1f}" y="{base_y + 13:.1f}" text-anchor="middle" '
                     f'font-size="9" fill="#52514e">{label}</text>')
        days = m["typical_close_days"]
        for r, val in enumerate((m["opened"], m["closed"],
                                 "\u2013" if days is None else f"{days:g}")):
            parts.append(f'<text x="{cx:.1f}" y="{base_y + 18 + row_h * (r + 1):.1f}" '
                         f'text-anchor="middle" font-size="9" fill="#1a1a1a">{val}</text>')

    for r, (name, color) in enumerate((("Opened", OPENED_COLOR), ("Closed", CLOSED_COLOR),
                                       ("Typical days to close", None))):
        yy = base_y + 18 + row_h * (r + 1)
        if color:
            parts.append(f'<rect x="0" y="{yy - 8:.1f}" width="9" height="9" rx="2" fill="{color}"/>')
        parts.append(f'<text x="{14 if color else 0}" y="{yy:.1f}" font-size="9" '
                     f'font-weight="700" fill="#52514e">{name}</text>')
    parts.append(f'<line x1="0" x2="{width - right}" y1="{base_y + 18 + 3:.1f}" '
                 f'y2="{base_y + 18 + 3:.1f}" stroke="#ebeae6" stroke-width="1"/>')
    parts.append("</svg>")
    return "".join(parts)
