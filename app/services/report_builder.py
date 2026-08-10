"""
Incident Report (AAR) generation for a single case.

Builds one plain-data dict from a Case and its related rows, then renders
that same dict to Markdown and to a Word document. Both renderers consume
`build_report_data()` output exclusively — neither one reaches back into
the ORM — so the two formats can never quietly drift apart from each other.

Structure and required content are traced to the Incident Management Plan,
Phase VI (Lessons Learned): chronological event sequence, method of
discovery, preventive measures implemented, and assessment of recovery
sufficiency are named there as mandatory. The severity classification
matrix is IMP Phase II. Closure sign-off authority is IMP §4.2 (CISO) and
§4.4 (IR Commander).
"""

import io
from datetime import date, datetime, timedelta

from app.models import utcnow

# ---------------------------------------------------------------------------
# IMP Phase II severity classification matrix
# ---------------------------------------------------------------------------

# (functional_impact, informational_impact) -> IMP severity label.
# None/None ("no effect, nothing accessed") isn't a codified incident under
# the matrix and has no cell — it stays unmapped on purpose.
_IMP_SEVERITY_MATRIX = {
    ("None", "Limited"): "Sev. 3", ("None", "Moderate"): "Sev. 2", ("None", "Critical"): "Sev. 1",
    ("Limited", "None"): "Sev. 3", ("Limited", "Limited"): "Sev. 3", ("Limited", "Moderate"): "Sev. 2", ("Limited", "Critical"): "Sev. 1",
    ("Moderate", "None"): "Sev. 2", ("Moderate", "Limited"): "Sev. 2", ("Moderate", "Moderate"): "Sev. 2", ("Moderate", "Critical"): "Sev. 1",
    ("Critical", "None"): "Sev. 1", ("Critical", "Limited"): "Sev. 1", ("Critical", "Moderate"): "Sev. 1", ("Critical", "Critical"): "Sev. 1",
}

# IMP §4.2 (CISO) / §4.4 (IR Commander): closure approval authority by severity.
_APPROVAL_AUTHORITY = {
    "Sev. 1": "CISO",
    "Sev. 2": "CISO or IR Commander",
    "Sev. 3": "IR Commander",
}


def imp_severity(functional_impact, informational_impact):
    """Return 'Sev. 1' / 'Sev. 2' / 'Sev. 3', or None if either axis is unset or unmapped."""
    if not functional_impact or not informational_impact:
        return None
    return _IMP_SEVERITY_MATRIX.get((functional_impact, informational_impact))


def approval_authority(imp_sev):
    return _APPROVAL_AUTHORITY.get(imp_sev)


# ---------------------------------------------------------------------------
# Small formatting helpers
# ---------------------------------------------------------------------------

def _fmt_dt(dt, fmt="%Y-%m-%d %H:%M"):
    return dt.strftime(fmt) if dt else None


def _fmt_date(d, fmt="%Y-%m-%d"):
    return d.strftime(fmt) if d else None


def _duration_str(start, end):
    if not start or not end or end < start:
        return None
    delta = end - start
    days, seconds = delta.days, delta.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours}h")
    if not days and minutes:
        parts.append(f"{minutes}m")
    return ", ".join(parts) if parts else "< 1m"


def _business_days_between(start, end):
    """Count business days (Mon-Fri) strictly between two dates, inclusive of end."""
    if not start or not end or end < start:
        return None
    count = 0
    d = start
    while d < end:
        d += timedelta(days=1)
        if d.weekday() < 5:
            count += 1
    return count


def _or_placeholder(value, placeholder="Not yet documented."):
    if value is None:
        return placeholder
    if isinstance(value, str) and not value.strip():
        return placeholder
    return value


def _short_hash(h, length=12):
    if not h:
        return "—"
    return h[:length] + "..." if len(h) > length else h


# ---------------------------------------------------------------------------
# Data assembly — the single source of truth both renderers read from
# ---------------------------------------------------------------------------

def build_report_data(case):
    """Assemble the full report content for *case* as a plain dict."""

    imp_sev = imp_severity(case.imp_functional_impact, case.imp_informational_impact)
    authority = approval_authority(imp_sev)

    # `.all()` if this is a lazy="dynamic" relationship (AppenderQuery), plain
    # `list()` if the caller passed an ordinary iterable (e.g. a test double)
    # — either way the explicit sort below is what actually orders it.
    timeline_events = list(case.timeline_events.all() if hasattr(case.timeline_events, "all") else case.timeline_events)
    iocs = list(case.iocs.all() if hasattr(case.iocs, "all") else case.iocs)
    evidence_items = list(case.evidence_items)
    status_history = list(case.status_history)
    deviations = list(case.deviations)
    recommendations = list(case.recommendations)

    # Chronological, oldest first, regardless of how the caller passed events in.
    timeline_events = sorted(timeline_events, key=lambda e: e.event_datetime)
    status_history = sorted(status_history, key=lambda s: s.recorded_at or utcnow())
    recommendations = sorted(recommendations, key=lambda r: r.id)

    timeline = []
    for ev in timeline_events:
        mitre = "—"
        if ev.mitre_tactic or ev.mitre_technique_id:
            mitre = " — ".join(x for x in [ev.mitre_tactic, ev.mitre_technique_id] if x)
        timeline.append({
            "time": _fmt_dt(ev.event_datetime),
            "phase": ev.category or "—",
            "description": ev.description,
            "mitre": mitre,
        })

    ioc_rows = [{
        "type": i.ioc_type,
        "value": i.value,
        "description": i.description or "—",
        "confidence": i.confidence or "—",
    } for i in iocs]

    evidence_rows = [{
        "evidence_id": e.evidence_id,
        "name": e.name,
        "type": e.evidence_type or "—",
        "collected_by": e.collected_by or "—",
        "sha256_short": _short_hash(e.hash_sha256),
    } for e in evidence_items]

    deviation_rows = [{
        "deviation": d.deviation,
        "standard_procedure": d.standard_procedure or "—",
        "justification": d.justification or "—",
        "approved_by": d.approved_by or "—",
    } for d in deviations]

    recommendation_rows = [{
        "n": idx + 1,
        "text": r.text,
        "disposition": r.disposition,
        "owner": r.owner or "—",
        "target": _fmt_date(r.target_date) or "—",
        "rtp_ref": r.risk_treatment_ref or "Pending",
        "status": r.status,
    } for idx, r in enumerate(recommendations)]

    status_history_rows = [{
        "date": _fmt_dt(s.recorded_at),
        "change": f"{s.old_status or '—'} → {s.new_status}",
        "notes": s.notes or "—",
    } for s in status_history]

    ll_sla_met = None
    ll_business_days = None
    if case.lessons_learned_date and case.closed_date:
        ll_business_days = _business_days_between(case.closed_date.date(), case.lessons_learned_date)
        if ll_business_days is not None:
            ll_sla_met = ll_business_days <= 5

    return {
        "case_id": case.case_id,
        "title": case.title,
        "case_type": case.case_type or "—",
        "cairn_severity": case.severity,
        "imp_functional_impact": case.imp_functional_impact,
        "imp_informational_impact": case.imp_informational_impact,
        "imp_severity": imp_sev,
        "approval_authority": authority,
        "status": case.status,
        "lead_analyst": case.lead_analyst.name if case.lead_analyst else "Unassigned",
        "escalated": case.escalated,
        "board_flagged": case.board_flagged,
        "opened": _fmt_dt(case.opened_date),
        "contained": _fmt_dt(case.contained_date),
        "eradicated": _fmt_dt(case.eradicated_date),
        "closed": _fmt_dt(case.closed_date),
        "duration": _duration_str(case.opened_date, case.closed_date),

        "description": _or_placeholder(case.description, "No executive summary recorded."),
        "method_of_discovery": _or_placeholder(case.method_of_discovery),
        "initial_vector": _or_placeholder(case.initial_vector),
        "affected_systems": _or_placeholder(case.affected_systems, "Not recorded."),
        "affected_users": _or_placeholder(case.affected_users, "Not recorded."),
        "estimated_impact": _or_placeholder(case.estimated_impact, "Not recorded."),

        "timeline": timeline,

        "iocs": ioc_rows,
        "evidence": evidence_rows,

        "root_cause": _or_placeholder(case.root_cause),

        "recovery_assessment": _or_placeholder(case.recovery_assessment),
        "recovery_sufficient": case.recovery_sufficient,

        "deviations": deviation_rows,

        "lessons_learned_date": _fmt_date(case.lessons_learned_date),
        "lessons_learned_attendees": _or_placeholder(case.lessons_learned_attendees, "Not recorded."),
        "lessons_learned_notes": _or_placeholder(case.lessons_learned_notes),
        "lessons_learned_sla_met": ll_sla_met,
        "lessons_learned_business_days": ll_business_days,

        "recommendations": recommendation_rows,

        "status_history": status_history_rows,

        "prepared_by": case.lead_analyst.name if case.lead_analyst else (case.created_by.name if case.created_by else "—"),
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def render_markdown(data: dict) -> str:
    lines = []
    a = lines.append

    a(f"# After Action Report — {data['case_id']}")
    a("")
    a(f"## {data['title']}")
    a("")
    a("| | |")
    a("|---|---|")
    a(f"| **Case ID** | {data['case_id']} |")
    a(f"| **Classification** | {data['case_type']} |")
    a(f"| **Cairn Severity** | {data['cairn_severity']} |")
    if data["imp_severity"]:
        detail = f"{data['imp_severity']} (Functional Impact: {data['imp_functional_impact']}; Informational Impact: {data['imp_informational_impact']})"
    else:
        detail = "Not yet classified — set Functional and Informational Impact on the Report tab."
    a(f"| **IMP Classification** | {detail} |")
    a(f"| **Status** | {data['status']} |")
    a(f"| **Lead Analyst** | {data['lead_analyst']} |")
    esc = "Yes" if data["escalated"] else "No"
    if data["board_flagged"]:
        esc += " — Board notified"
    a(f"| **Escalated** | {esc} |")
    a(f"| **Opened** | {data['opened'] or '—'} |")
    a(f"| **Contained** | {data['contained'] or '—'} |")
    a(f"| **Eradicated** | {data['eradicated'] or '—'} |")
    a(f"| **Closed** | {data['closed'] or '—'} |")
    a(f"| **Total Duration** | {data['duration'] or '—'} |")
    a("")
    a("---")
    a("")

    a("## Executive Summary")
    a("")
    a(data["description"])
    a("")

    a("## Incident Overview")
    a("")
    a(f"**Method of Discovery:** {data['method_of_discovery']}")
    a("")
    a(f"**Initial Vector:** {data['initial_vector']}")
    a("")
    a(f"**Affected Systems:** {data['affected_systems']}")
    a("")
    a(f"**Affected Users:** {data['affected_users']}")
    a("")
    a(f"**Estimated Impact:** {data['estimated_impact']}")
    a("")

    a("## Timeline of Events")
    a("")
    if data["timeline"]:
        a("| Time (UTC) | Phase | Description | MITRE ATT&CK |")
        a("|---|---|---|---|")
        for t in data["timeline"]:
            a(f"| {t['time']} | {t['phase']} | {t['description']} | {t['mitre']} |")
    else:
        a("No timeline events recorded.")
    a("")

    a("## Indicators of Compromise")
    a("")
    if data["iocs"]:
        a("| Type | Value | Description | Confidence |")
        a("|---|---|---|---|")
        for i in data["iocs"]:
            a(f"| {i['type']} | {i['value']} | {i['description']} | {i['confidence']} |")
    else:
        a("No IOCs recorded.")
    a("")

    a("## Evidence Collected")
    a("")
    if data["evidence"]:
        a("| Evidence ID | Name | Type | Collected By | SHA-256 |")
        a("|---|---|---|---|---|")
        for e in data["evidence"]:
            a(f"| {e['evidence_id']} | {e['name']} | {e['type']} | {e['collected_by']} | {e['sha256_short']} |")
        a("")
        a("*Full chain-of-custody detail is retained in Cairn per each evidence record; hashes are truncated here for readability.*")
    else:
        a("No evidence recorded.")
    a("")

    a("## Root Cause")
    a("")
    a(data["root_cause"])
    a("")

    a("## Recovery Sufficiency Assessment")
    a("")
    a(f"**Assessment: {data['recovery_sufficient'] or 'Not yet assessed'}.**")
    a("")
    a(data["recovery_assessment"])
    a("")

    a("## Deviations from Standard Procedure")
    a("")
    if data["deviations"]:
        a("| Deviation | Standard Procedure | Justification | Approved By |")
        a("|---|---|---|---|")
        for d in data["deviations"]:
            a(f"| {d['deviation']} | {d['standard_procedure']} | {d['justification']} | {d['approved_by']} |")
    else:
        a("No deviations from standard procedure recorded.")
    a("")

    a("## Lessons Learned Meeting")
    a("")
    if data["lessons_learned_date"]:
        sla = ""
        if data["lessons_learned_sla_met"] is True:
            sla = f" ({data['lessons_learned_business_days']} business days post-closure — within the IMP's 5-business-day requirement)"
        elif data["lessons_learned_sla_met"] is False:
            sla = f" ({data['lessons_learned_business_days']} business days post-closure — outside the IMP's 5-business-day requirement)"
        a(f"Held {data['lessons_learned_date']}{sla}.")
        a("")
        a(f"**Attendees:** {data['lessons_learned_attendees']}")
    else:
        a("Not yet held or not yet recorded. IMP Phase VI requires this meeting within 5 business days of closure.")
    a("")
    a(data["lessons_learned_notes"])
    a("")

    a("## Recommendations")
    a("")
    if data["recommendations"]:
        a("| # | Recommendation | Disposition | Owner | Target | RTP Ref. |")
        a("|---|---|---|---|---|---|")
        for r in data["recommendations"]:
            a(f"| {r['n']} | {r['text']} | {r['disposition']} | {r['owner']} | {r['target']} | {r['rtp_ref']} |")
        a("")
        a("*Per IMP Phase VI, every identified gap must resolve to remediation, a compensating control, or a formal, documented risk acceptance, and be logged against the organizational risk treatment plan.*")
    else:
        a("No recommendations recorded.")
    a("")

    a("## Case Status History")
    a("")
    if data["status_history"]:
        a("| Date/Time | Change | Notes |")
        a("|---|---|---|")
        for s in data["status_history"]:
            a(f"| {s['date']} | {s['change']} | {s['notes']} |")
    else:
        a("No status changes recorded.")
    a("")
    a("---")
    a("")

    a("## Approval")
    a("")
    if data["imp_severity"]:
        a(f"**Approval authority (per IMP §4.2 / §4.4):** This incident is classified {data['imp_severity']}. Closure requires approval from: {data['approval_authority']}.")
    else:
        a("**Approval authority:** Not yet determined — set Functional and Informational Impact on the Report tab to compute the IMP severity classification and required approver.")
    a("")
    a(f"*Report generated from Cairn case {data['case_id']} on {data['generated_at']}. Prepared by {data['prepared_by']}.*")
    a("")
    a("Approved by: ____________________________&nbsp;&nbsp;&nbsp;&nbsp;Date: ______________")
    a("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DOCX renderer
# ---------------------------------------------------------------------------

def render_docx(data: dict) -> io.BytesIO:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    NAVY = RGBColor(0x1F, 0x38, 0x64)
    RED = RGBColor(0xC0, 0x00, 0x00)
    GREY = RGBColor(0x59, 0x59, 0x59)
    LIGHTGREY = "F2F2F2"
    AMBER = "FDEBD0"

    doc = Document()

    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = section.right_margin = Inches(0.75)
    section.top_margin = section.bottom_margin = Inches(0.75)

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)

    h1 = doc.styles["Heading 1"]
    h1.font.name = "Calibri"
    h1.font.size = Pt(20)
    h1.font.color.rgb = NAVY
    h1.font.bold = True

    h2 = doc.styles["Heading 2"]
    h2.font.name = "Calibri"
    h2.font.size = Pt(14)
    h2.font.color.rgb = NAVY
    h2.font.bold = True

    def shade_cell(cell, hex_color):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        tcPr.append(shd)

    def set_cell_text(cell, text, bold=False, color=None, size=9.5, italic=False):
        cell.text = ""
        p = cell.paragraphs[0]
        run = p.add_run(str(text))
        run.bold = bold
        run.italic = italic
        run.font.size = Pt(size)
        if color:
            run.font.color.rgb = color

    def add_table(headers, rows, widths=None):
        table = doc.add_table(rows=1, cols=len(headers))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = True
        hdr = table.rows[0].cells
        for i, h in enumerate(headers):
            set_cell_text(hdr[i], h, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF), size=9.5)
            shade_cell(hdr[i], "1F3864")
        for ri, row in enumerate(rows):
            cells = table.add_row().cells
            for i, val in enumerate(row):
                set_cell_text(cells[i], val, size=9.5)
                if ri % 2 == 1:
                    shade_cell(cells[i], LIGHTGREY)
        doc.add_paragraph()
        return table

    def add_info_table(pairs):
        table = doc.add_table(rows=0, cols=2)
        table.autofit = True
        for label, value, *shade in pairs:
            row = table.add_row().cells
            set_cell_text(row[0], label, bold=True, size=9.5)
            shade_cell(row[0], LIGHTGREY)
            set_cell_text(row[1], value, size=9.5)
            if shade:
                shade_cell(row[1], shade[0])
        doc.add_paragraph()

    def add_heading(text):
        doc.add_heading(text, level=2)

    def add_para(text, bold=False, italic=False, color=None, size=None):
        p = doc.add_paragraph()
        run = p.add_run(str(text))
        run.bold = bold
        run.italic = italic
        if color:
            run.font.color.rgb = color
        if size:
            run.font.size = Pt(size)
        return p

    # ── Title block ──────────────────────────────────────────────────────
    kicker = doc.add_paragraph()
    kr = kicker.add_run("AFTER ACTION REPORT")
    kr.bold = True
    kr.font.color.rgb = RED
    kr.font.size = Pt(10)

    doc.add_heading(f"{data['case_id']} — {data['title']}", level=1)

    imp_detail = (
        f"{data['imp_severity']} (Functional Impact: {data['imp_functional_impact']}; "
        f"Informational Impact: {data['imp_informational_impact']})"
        if data["imp_severity"]
        else "Not yet classified — set Functional and Informational Impact on the Report tab."
    )
    esc = "Yes" if data["escalated"] else "No"
    if data["board_flagged"]:
        esc += " — Board notified"

    add_info_table([
        ("Case ID", data["case_id"]),
        ("Classification", data["case_type"]),
        ("Cairn Severity", data["cairn_severity"]),
        ("IMP Classification", imp_detail, AMBER),
        ("Status", data["status"]),
        ("Lead Analyst", data["lead_analyst"]),
        ("Escalated", esc),
        ("Opened", data["opened"] or "—"),
        ("Contained", data["contained"] or "—"),
        ("Eradicated", data["eradicated"] or "—"),
        ("Closed", data["closed"] or "—"),
        ("Total Duration", data["duration"] or "—"),
    ])

    add_heading("Executive Summary")
    add_para(data["description"])

    add_heading("Incident Overview")
    add_para(f"Method of Discovery: {data['method_of_discovery']}")
    add_para(f"Initial Vector: {data['initial_vector']}")
    add_para(f"Affected Systems: {data['affected_systems']}")
    add_para(f"Affected Users: {data['affected_users']}")
    add_para(f"Estimated Impact: {data['estimated_impact']}")

    add_heading("Timeline of Events")
    if data["timeline"]:
        add_table(
            ["Time (UTC)", "Phase", "Description", "MITRE ATT&CK"],
            [[t["time"], t["phase"], t["description"], t["mitre"]] for t in data["timeline"]],
        )
    else:
        add_para("No timeline events recorded.", italic=True, color=GREY)

    add_heading("Indicators of Compromise")
    if data["iocs"]:
        add_table(
            ["Type", "Value", "Description", "Confidence"],
            [[i["type"], i["value"], i["description"], i["confidence"]] for i in data["iocs"]],
        )
    else:
        add_para("No IOCs recorded.", italic=True, color=GREY)

    add_heading("Evidence Collected")
    if data["evidence"]:
        add_table(
            ["Evidence ID", "Name", "Type", "Collected By", "SHA-256"],
            [[e["evidence_id"], e["name"], e["type"], e["collected_by"], e["sha256_short"]] for e in data["evidence"]],
        )
        add_para(
            "Full chain-of-custody detail is retained in Cairn per each evidence record; "
            "hashes are truncated here for readability.",
            italic=True, color=GREY, size=8.5,
        )
    else:
        add_para("No evidence recorded.", italic=True, color=GREY)

    add_heading("Root Cause")
    add_para(data["root_cause"])

    add_heading("Recovery Sufficiency Assessment")
    add_para(f"Assessment: {data['recovery_sufficient'] or 'Not yet assessed'}.", bold=True)
    add_para(data["recovery_assessment"])

    add_heading("Deviations from Standard Procedure")
    if data["deviations"]:
        add_table(
            ["Deviation", "Standard Procedure", "Justification", "Approved By"],
            [[d["deviation"], d["standard_procedure"], d["justification"], d["approved_by"]] for d in data["deviations"]],
        )
    else:
        add_para("No deviations from standard procedure recorded.", italic=True, color=GREY)

    add_heading("Lessons Learned Meeting")
    if data["lessons_learned_date"]:
        sla = ""
        if data["lessons_learned_sla_met"] is True:
            sla = f" ({data['lessons_learned_business_days']} business days post-closure — within the IMP's 5-business-day requirement)"
        elif data["lessons_learned_sla_met"] is False:
            sla = f" ({data['lessons_learned_business_days']} business days post-closure — outside the IMP's 5-business-day requirement)"
        add_para(f"Held {data['lessons_learned_date']}{sla}.")
        add_para(f"Attendees: {data['lessons_learned_attendees']}")
    else:
        add_para(
            "Not yet held or not yet recorded. IMP Phase VI requires this meeting "
            "within 5 business days of closure.",
            italic=True, color=GREY,
        )
    add_para(data["lessons_learned_notes"])

    add_heading("Recommendations")
    if data["recommendations"]:
        add_table(
            ["#", "Recommendation", "Disposition", "Owner", "Target", "RTP Ref."],
            [[r["n"], r["text"], r["disposition"], r["owner"], r["target"], r["rtp_ref"]] for r in data["recommendations"]],
        )
        add_para(
            "Per IMP Phase VI, every identified gap must resolve to remediation, a compensating "
            "control, or a formal, documented risk acceptance, and be logged against the "
            "organizational risk treatment plan.",
            italic=True, color=GREY, size=8.5,
        )
    else:
        add_para("No recommendations recorded.", italic=True, color=GREY)

    add_heading("Case Status History")
    if data["status_history"]:
        add_table(
            ["Date/Time", "Change", "Notes"],
            [[s["date"], s["change"], s["notes"]] for s in data["status_history"]],
        )
    else:
        add_para("No status changes recorded.", italic=True, color=GREY)

    add_heading("Approval")
    if data["imp_severity"]:
        add_para(
            f"Approval authority (per IMP §4.2 / §4.4): This incident is classified "
            f"{data['imp_severity']}. Closure requires approval from: {data['approval_authority']}.",
            bold=True,
        )
    else:
        add_para(
            "Approval authority: Not yet determined — set Functional and Informational Impact "
            "on the Report tab to compute the IMP severity classification and required approver.",
            bold=True,
        )
    add_para(
        f"Report generated from Cairn case {data['case_id']} on {data['generated_at']}. "
        f"Prepared by {data['prepared_by']}.",
        italic=True, color=GREY, size=9,
    )
    add_para("Approved by: ____________________________          Date: ______________")

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf
