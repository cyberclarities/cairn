from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(16), nullable=False, default="viewer")  # admin / analyst / viewer
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_sso_user = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Failed-login lockout. Persisted rather than held in memory so it survives
    # a restart and cannot be reset by bouncing the container.
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # SSO accounts carry no local password; never let an empty hash pass.
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def is_locked_out(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_analyst(self):
        return self.role in ("admin", "analyst")

    def __repr__(self):
        return f"<User {self.username}>"


# ---------------------------------------------------------------------------
# Case
# ---------------------------------------------------------------------------

class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)

    severity = db.Column(db.String(16), nullable=False, default="Medium")
    # Critical / High / Medium / Low / Informational

    status = db.Column(db.String(32), nullable=False, default="New")
    # New / In Progress / Contained / Eradicated / Recovered / Closed

    case_type = db.Column(db.String(64))
    # Ransomware / Data Breach / Phishing / BEC / Malware / Insider Threat /
    # DDoS / Unauthorized Access / Vulnerability Exploitation / Other

    affected_systems = db.Column(db.Text)
    affected_users = db.Column(db.Text)
    estimated_impact = db.Column(db.Text)
    initial_vector = db.Column(db.Text)

    lead_analyst_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    lead_analyst = db.relationship("User", foreign_keys=[lead_analyst_id])

    escalated = db.Column(db.Boolean, default=False, nullable=False)
    board_flagged = db.Column(db.Boolean, default=False, nullable=False)

    opened_date = db.Column(db.DateTime, default=utcnow)
    contained_date = db.Column(db.DateTime, nullable=True)
    eradicated_date = db.Column(db.DateTime, nullable=True)
    closed_date = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    # ── Incident Report / AAR fields ─────────────────────────────────────
    # Everything below is nullable by design — a case with none of this
    # filled in still produces a report; the renderer shows "not yet
    # documented" placeholders instead of failing. See
    # app/services/report_builder.py.

    # Free text: how the incident was first identified (automated detection,
    # user report, third party, audit finding, ...). IMP Phase VI requires
    # this named explicitly in the formal Incident Report.
    method_of_discovery = db.Column(db.Text, nullable=True)

    # Distinct from initial_vector: initial_vector is the entry point (how
    # the attacker got in); root_cause is the underlying condition that made
    # it possible (e.g. "RDP exposed to the internet with a weak local admin
    # credential"). Reports often need both.
    root_cause = db.Column(db.Text, nullable=True)

    # IMP Phase VI requires "assessment of recovery sufficiency" as a named
    # judgment, not just a narrative of what was restored.
    recovery_assessment = db.Column(db.Text, nullable=True)
    recovery_sufficient = db.Column(db.String(32), nullable=True)
    # Sufficient / Partially Sufficient / Insufficient — config.RECOVERY_ASSESSMENTS

    # IMP Phase II severity classification matrix (Functional Impact x
    # Informational Impact -> Sev. 1/2/3). Deliberately independent of
    # `severity` above: that field drives Cairn's own triage/dashboard and
    # stays a simple Critical/High/Medium/Low label; this pair is the IMP's
    # own two-axis classification and determines closure sign-off authority
    # per IMP §4.2/§4.4. Left blank rather than inferred from `severity` —
    # the two scales don't map cleanly onto each other, and a guessed
    # classification in a compliance document is worse than an honest blank.
    imp_functional_impact = db.Column(db.String(16), nullable=True)
    imp_informational_impact = db.Column(db.String(16), nullable=True)

    # IMP Phase VI: Lessons Learned meeting must be held within 5 business
    # days of closure. Recorded here so the report can state whether that
    # SLA was met instead of asserting it.
    lessons_learned_date = db.Column(db.Date, nullable=True)
    lessons_learned_attendees = db.Column(db.Text, nullable=True)
    # Free-form meeting notes. The Report tab prompts with the IMP's own
    # meeting questions (were procedures followed, what delayed response,
    # how could external information-sharing improve, ...) as guidance
    # rather than splitting this into a rigid What-Went-Well/What-Could-
    # Improve schema — it's meeting notes, not structured data.
    lessons_learned_notes = db.Column(db.Text, nullable=True)

    # Relationships
    iocs = db.relationship("IOC", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    evidence_items = db.relationship("Evidence", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    timeline_events = db.relationship("TimelineEvent", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    audit_entries = db.relationship("AuditLog", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    status_history = db.relationship("CaseStatusHistory", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    deviations = db.relationship("CaseDeviation", backref="case", lazy="dynamic", cascade="all, delete-orphan")
    recommendations = db.relationship("Recommendation", backref="case", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def severity_color(self):
        return {
            "Critical": "danger",
            "High": "warning",
            "Medium": "primary",
            "Low": "info",
            "Informational": "secondary",
        }.get(self.severity, "secondary")

    @property
    def status_color(self):
        return {
            "New": "danger",
            "In Progress": "warning",
            "Contained": "info",
            "Eradicated": "primary",
            "Recovered": "success",
            "Closed": "secondary",
        }.get(self.status, "secondary")

    def __repr__(self):
        return f"<Case {self.case_id}>"


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------

class IOC(db.Model):
    __tablename__ = "iocs"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    ioc_type = db.Column(db.String(32), nullable=False)
    # IP Address / IPv6 Address / Domain / URL / File Hash MD5 / File Hash SHA1 /
    # File Hash SHA256 / Email Address / Registry Key / File Name/Path /
    # User Account / Mutex / CVE / Other

    value = db.Column(db.String(1024), nullable=False)
    description = db.Column(db.Text)
    confidence = db.Column(db.String(8), default="Medium")  # High / Medium / Low
    status = db.Column(db.String(16), default="Active")  # Active / Resolved / False Positive
    source = db.Column(db.String(256))
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User")

    @property
    def confidence_color(self):
        return {"High": "danger", "Medium": "warning", "Low": "secondary"}.get(self.confidence, "secondary")

    @property
    def status_color(self):
        return {"Active": "danger", "Resolved": "success", "False Positive": "secondary"}.get(self.status, "secondary")

    @property
    def case_is_closed(self):
        """
        Whether the parent case is closed.

        Deliberately not stored on the IOC itself. Closing a case doesn't
        change what actually happened to an indicator — an IOC marked
        Resolved or False Positive keeps saying that. This just lets
        templates show an additional "Case Closed" tag without the case's
        status ever overwriting the IOC's own.
        """
        return self.case is not None and self.case.status == "Closed"

    def __repr__(self):
        return f"<IOC {self.ioc_type}:{self.value[:40]}>"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)

    evidence_type = db.Column(db.String(64))
    # Disk Image / Memory Dump / Log File / Network Capture / Email/PST /
    # Document / Database Dump / Malware Sample / Screenshot / Other

    source_system = db.Column(db.String(256))
    hash_md5 = db.Column(db.String(32))
    hash_sha256 = db.Column(db.String(64))
    size_bytes = db.Column(db.BigInteger, nullable=True)

    # Set only when a file was uploaded through the app (as opposed to an
    # evidence record describing something collected and stored elsewhere).
    # file_path is relative to EVIDENCE_STORAGE_PATH and server-generated —
    # see app/services/evidence_storage.py — never taken from request input.
    file_path = db.Column(db.String(512), nullable=True)
    original_filename = db.Column(db.String(256), nullable=True)
    mime_type = db.Column(db.String(128), nullable=True)

    # Set on every download: the file is re-hashed against hash_sha256 so a
    # change to the bytes on disk is caught at the point someone relies on
    # them, not just noted once at upload and trusted forever after.
    hash_verified_at = db.Column(db.DateTime, nullable=True)
    hash_verified_ok = db.Column(db.Boolean, nullable=True)

    collected_by = db.Column(db.String(128))
    collection_date = db.Column(db.Date, nullable=True)
    storage_location = db.Column(db.String(512))

    status = db.Column(db.String(16), default="Collected")
    # Collected / In Analysis / Analyzed / Archived

    chain_of_custody = db.Column(db.Text)
    notes = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User")

    @property
    def has_file(self):
        return bool(self.file_path)

    @property
    def status_color(self):
        return {
            "Collected": "primary",
            "In Analysis": "warning",
            "Analyzed": "success",
            "Archived": "secondary",
        }.get(self.status, "secondary")

    def __repr__(self):
        return f"<Evidence {self.evidence_id}>"


# ---------------------------------------------------------------------------
# Timeline Event
# ---------------------------------------------------------------------------

# Fixed 7-slot palette. The hex values themselves are not admin-editable —
# only the label attached to each slot is (see LookupValue list_name
# "timeline_color", keyed by display_order 1-7 in settings.py). Position in
# this list *is* the slot number; do not reorder it, only append is safe if
# the palette ever needs to grow.
TIMELINE_COLORS = [
    "#dc3545",  # 1 red
    "#fd7e14",  # 2 orange
    "#ffc107",  # 3 amber
    "#198754",  # 4 green
    "#20c997",  # 5 teal
    "#0d6efd",  # 6 blue
    "#6f42c1",  # 7 purple
]

# Many-to-many: a timeline event can reference several IOCs from the same
# case, and an IOC can show up on several events. A plain association table
# (no extra columns) is all either side needs.
timeline_event_iocs = db.Table(
    "timeline_event_iocs",
    db.Column("timeline_event_id", db.Integer, db.ForeignKey("timeline_events.id"), primary_key=True),
    db.Column("ioc_id", db.Integer, db.ForeignKey("iocs.id"), primary_key=True),
)


class TimelineEvent(db.Model):
    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    event_datetime = db.Column(db.DateTime, nullable=False)

    # The timezone the analyst actually entered the time in, before it was
    # converted to UTC for storage. Purely a record of intent — event_datetime
    # is always UTC and is what every query/sort/display uses. Kept around so
    # "what did the analyst actually type" is answerable later.
    source_timezone = db.Column(db.String(64), default="UTC")

    event_type = db.Column(db.String(64), nullable=True)
    # Maps to MITRE ATT&CK tactic names (optional; mitre_tactic is the primary field)

    description = db.Column(db.Text, nullable=False)
    source_artifact = db.Column(db.String(256))

    mitre_tactic = db.Column(db.String(64))
    mitre_technique = db.Column(db.String(128))
    mitre_technique_id = db.Column(db.String(16))

    ioc_reference = db.Column(db.Text)
    # Legacy free-text IOC notes, kept for records written before the
    # structured link below existed. New events use `iocs`.
    iocs = db.relationship("IOC", secondary=timeline_event_iocs,
                            backref=db.backref("timeline_events", lazy="dynamic"))

    confidence = db.Column(db.String(8), default="Medium")  # High / Medium / Low

    # Admin-defined dropdown — see LookupValue list_name "timeline_category".
    category = db.Column(db.String(64), nullable=True)

    # Single free-text sorting tag.
    tag = db.Column(db.String(64), nullable=True)

    # Index into TIMELINE_COLORS (1-7), or None for no color.
    color_slot = db.Column(db.Integer, nullable=True)

    # Newline-separated subset of the case's affected_systems text. Stored as
    # a plain snapshot rather than a foreign key — Cairn has no structured
    # Asset entity, so this records which of the strings the case listed at
    # the time were relevant to this event, not a live reference to them.
    affected_assets = db.Column(db.Text, nullable=True)

    # Self-referential parent. ON DELETE SET NULL means deleting a parent row
    # never leaves a dangling reference at the database level regardless of
    # the order the ORM issues statements in (relevant for case cascade
    # delete, which removes every timeline event in one go) — the app-level
    # delete_event route re-parents children explicitly for a single delete,
    # this is the backstop for bulk deletes.
    parent_id = db.Column(db.Integer, db.ForeignKey("timeline_events.id", ondelete="SET NULL"),
                           nullable=True, index=True)
    parent = db.relationship("TimelineEvent", remote_side=[id],
                              backref=db.backref("children", lazy="dynamic"))

    # Source alert, when this event was auto-created by promoting or linking
    # an Alert to a case. Alerts are purgeable independent of case history
    # (see settings.purge_alerts — a bulk DELETE) so this is nullable with
    # ON DELETE SET NULL: purging the alert row must never take the timeline
    # record of what happened along with it.
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="SET NULL"),
                          nullable=True, index=True)
    alert = db.relationship("Alert", backref=db.backref("timeline_events", lazy="dynamic"))

    created_at = db.Column(db.DateTime, default=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User")

    @property
    def confidence_color(self):
        return {"High": "danger", "Medium": "warning", "Low": "secondary"}.get(self.confidence, "secondary")

    @property
    def color_hex(self):
        if self.color_slot and 1 <= self.color_slot <= len(TIMELINE_COLORS):
            return TIMELINE_COLORS[self.color_slot - 1]
        return None

    @property
    def affected_assets_list(self):
        if not self.affected_assets:
            return []
        return [line for line in self.affected_assets.splitlines() if line.strip()]

    def __repr__(self):
        return f"<TimelineEvent {self.event_datetime} {self.mitre_technique_id}>"


# ---------------------------------------------------------------------------
# Case Status History
# ---------------------------------------------------------------------------

class CaseStatusHistory(db.Model):
    __tablename__ = "case_status_history"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    old_status = db.Column(db.String(32))
    new_status = db.Column(db.String(32))
    notes = db.Column(db.Text)
    recorded_at = db.Column(db.DateTime, default=utcnow)
    recorded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    recorded_by = db.relationship("User")


# ---------------------------------------------------------------------------
# Case Deviation — IMP Phase VI documentation requirement: deviations from
# standard procedure must be recorded with a justification, not just noted
# informally in a timeline entry.
# ---------------------------------------------------------------------------

class CaseDeviation(db.Model):
    __tablename__ = "case_deviations"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    deviation = db.Column(db.Text, nullable=False)
    standard_procedure = db.Column(db.Text, nullable=True)
    justification = db.Column(db.Text, nullable=True)
    approved_by = db.Column(db.String(128), nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User")

    def __repr__(self):
        return f"<CaseDeviation case={self.case_id} {self.deviation[:40]!r}>"


# ---------------------------------------------------------------------------
# Recommendation — IMP Phase VI: every identified gap must resolve to
# remediation, a compensating control, or a documented risk acceptance, and
# feed the organizational risk treatment plan.
# ---------------------------------------------------------------------------

class Recommendation(db.Model):
    __tablename__ = "recommendations"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    text = db.Column(db.Text, nullable=False)
    disposition = db.Column(db.String(32), nullable=False, default="Remediation")
    # Remediation / Compensating Control / Risk Acceptance — config.RECOMMENDATION_DISPOSITIONS

    owner = db.Column(db.String(128), nullable=True)
    target_date = db.Column(db.Date, nullable=True)
    risk_treatment_ref = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), nullable=False, default="Open")  # Open / Complete

    # Required (enforced at the route, not the schema — see case_report.py)
    # when disposition is Risk Acceptance.
    risk_acceptance_justification = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User")

    @property
    def disposition_color(self):
        return {
            "Remediation": "success",
            "Compensating Control": "warning",
            "Risk Acceptance": "danger",
        }.get(self.disposition, "secondary")

    def __repr__(self):
        return f"<Recommendation case={self.case_id} {self.disposition}>"


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True, index=True)
    entity_type = db.Column(db.String(32))  # case / ioc / evidence / timeline_event / user
    entity_id = db.Column(db.Integer)
    field_name = db.Column(db.String(64))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    changed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    changed_by = db.relationship("User")
    changed_at = db.Column(db.DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Lookup Tables (configurable via admin settings)
# ---------------------------------------------------------------------------

class LookupValue(db.Model):
    __tablename__ = "lookup_values"

    id = db.Column(db.Integer, primary_key=True)
    list_name = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.String(256), nullable=False)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<LookupValue {self.list_name}:{self.value}>"


# ---------------------------------------------------------------------------
# Identifier counters — single source of truth for CASE / EVIDENCE numbering
# ---------------------------------------------------------------------------

class IdCounter(db.Model):
    """
    Monotonic counter per identifier prefix.

    Replaces "read the newest row, parse its number, add one", which had three
    failure modes: two analysts creating records at the same moment could claim
    the same ID, deleting the newest record handed its number to the next one,
    and an unparseable legacy ID sent the counter back to 1. A counter row taken
    under a row lock has none of those.
    """
    __tablename__ = "id_counters"

    name = db.Column(db.String(32), primary_key=True)   # 'case' | 'evidence'
    last_value = db.Column(db.Integer, nullable=False, default=0)

    @classmethod
    def next_value(cls, name: str, start_at: int = 0) -> int:
        """
        Reserve and return the next integer for *name*.

        Locks the counter row (SELECT ... FOR UPDATE on PostgreSQL) so concurrent
        callers serialise. Must be called inside a transaction; the caller commits.
        """
        row = db.session.get(cls, name, with_for_update=True)
        if row is None:
            row = cls(name=name, last_value=start_at)
            db.session.add(row)
            db.session.flush()
            # Re-read under lock in case another worker inserted first.
            row = db.session.get(cls, name, with_for_update=True)
        row.last_value += 1
        db.session.flush()
        return row.last_value


# ---------------------------------------------------------------------------
# Integration poll state — high-water mark per source
# ---------------------------------------------------------------------------

class PollState(db.Model):
    """
    Last successfully ingested timestamp per alert source.

    Without this, each poll asked for a fixed trailing window. A failed poll, a
    restart, or a burst larger than the page size dropped alerts permanently and
    silently — a detection gap, not a performance one. Queries now run forward
    from this mark, so a late poll catches up instead of skipping.
    """
    __tablename__ = "poll_state"

    source = db.Column(db.String(32), primary_key=True)   # 'crowdstrike' | 'proofpoint'
    last_event_at = db.Column(db.DateTime, nullable=True)
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(16))                # 'ok' | 'error'
    last_error = db.Column(db.Text)
    consecutive_failures = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f"<PollState {self.source} @ {self.last_event_at}>"


# ---------------------------------------------------------------------------
# Alert  (CrowdStrike + Proofpoint TAP, unified queue)
# ---------------------------------------------------------------------------

class Alert(db.Model):
    __tablename__ = "alerts"
    __table_args__ = (
        # Dedup: same external ID can appear in different sources
        db.UniqueConstraint("source", "external_id", name="uq_alert_source_external_id"),
    )

    id = db.Column(db.Integer, primary_key=True)

    # Source system: 'crowdstrike' | 'proofpoint'
    source = db.Column(db.String(32), nullable=False, default="crowdstrike", index=True)

    # Deduplication key — composite_id (CS) or GUID (Proofpoint)
    external_id = db.Column(db.String(255), nullable=False, index=True)

    # MITRE / detection context
    tactic = db.Column(db.String(100))
    technique = db.Column(db.String(100))
    technique_id = db.Column(db.String(20))
    objective = db.Column(db.String(150))
    scenario = db.Column(db.String(255))

    # Severity (normalised: 1-100 integer + name across all sources)
    severity = db.Column(db.Integer, default=0)
    severity_name = db.Column(db.String(20))   # Critical / High / Medium / Low / Informational

    # Host context
    host_hostname = db.Column(db.String(255))
    host_ip = db.Column(db.String(50))
    host_platform = db.Column(db.String(50))

    # User context
    username = db.Column(db.String(255))

    # Description / summary
    description = db.Column(db.Text)

    # Full raw JSON from source for reference
    raw_json = db.Column(db.Text)

    # Timestamps
    cs_created_at = db.Column(db.DateTime, nullable=True)   # when source detected it
    fetched_at = db.Column(db.DateTime, default=utcnow)     # when CAIRN pulled it

    # Workflow status: new → reviewing → promoted (linked to case) | dismissed
    status = db.Column(db.String(20), nullable=False, default="new", index=True)

    # Review metadata
    notes = db.Column(db.Text)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])
    reviewed_at = db.Column(db.DateTime, nullable=True)

    # Link to case after promotion (multiple alerts can share one case — merge)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True, index=True)
    case = db.relationship("Case", backref=db.backref("alerts", lazy="dynamic"))

    @property
    def source_label(self):
        return {"crowdstrike": "CrowdStrike", "proofpoint": "Proofpoint"}.get(self.source, self.source.title())

    @property
    def source_color(self):
        return {"crowdstrike": "danger", "proofpoint": "primary"}.get(self.source, "secondary")

    @property
    def severity_color(self):
        return {
            "Critical": "danger",
            "High": "warning",
            "Medium": "primary",
            "Low": "success",
            "Informational": "secondary",
        }.get(self.severity_name, "secondary")

    @property
    def status_color(self):
        return {
            "new": "danger",
            "reviewing": "warning",
            "promoted": "success",
            "dismissed": "secondary",
        }.get(self.status, "secondary")

    def __repr__(self):
        return f"<Alert {self.source}:{self.external_id} [{self.status}]>"
