"""
Seed data: MITRE ATT&CK tactics/techniques and default lookup values.
Called once on first startup when the database is empty.
"""

# MITRE ATT&CK v14 — key tactics and most-encountered techniques
MITRE_DATA = {
    "Reconnaissance": {
        "id": "TA0043",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning"},
            {"id": "T1592", "name": "Gather Victim Host Information"},
            {"id": "T1589", "name": "Gather Victim Identity Information"},
            {"id": "T1590", "name": "Gather Victim Network Information"},
            {"id": "T1591", "name": "Gather Victim Org Information"},
            {"id": "T1598", "name": "Phishing for Information"},
            {"id": "T1597", "name": "Search Closed Sources"},
            {"id": "T1596", "name": "Search Open Technical Databases"},
            {"id": "T1593", "name": "Search Open Websites/Domains"},
            {"id": "T1594", "name": "Search Victim-Owned Websites"},
        ],
    },
    "Resource Development": {
        "id": "TA0042",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure"},
            {"id": "T1586", "name": "Compromise Accounts"},
            {"id": "T1584", "name": "Compromise Infrastructure"},
            {"id": "T1587", "name": "Develop Capabilities"},
            {"id": "T1585", "name": "Establish Accounts"},
            {"id": "T1588", "name": "Obtain Capabilities"},
            {"id": "T1608", "name": "Stage Capabilities"},
        ],
    },
    "Initial Access": {
        "id": "TA0001",
        "techniques": [
            {"id": "T1189", "name": "Drive-by Compromise"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1133", "name": "External Remote Services"},
            {"id": "T1200", "name": "Hardware Additions"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
            {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
            {"id": "T1091", "name": "Replication Through Removable Media"},
            {"id": "T1195", "name": "Supply Chain Compromise"},
            {"id": "T1199", "name": "Trusted Relationship"},
            {"id": "T1078", "name": "Valid Accounts"},
        ],
    },
    "Execution": {
        "id": "TA0002",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"},
            {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell"},
            {"id": "T1059.006", "name": "Command and Scripting Interpreter: Python"},
            {"id": "T1609", "name": "Container Administration Command"},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
            {"id": "T1106", "name": "Native API"},
            {"id": "T1053", "name": "Scheduled Task/Job"},
            {"id": "T1569", "name": "System Services"},
            {"id": "T1204", "name": "User Execution"},
            {"id": "T1204.001", "name": "User Execution: Malicious Link"},
            {"id": "T1204.002", "name": "User Execution: Malicious File"},
            {"id": "T1047", "name": "Windows Management Instrumentation"},
        ],
    },
    "Persistence": {
        "id": "TA0003",
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
            {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys"},
            {"id": "T1547.004", "name": "Boot or Logon Autostart Execution: Winlogon Helper DLL"},
            {"id": "T1136", "name": "Create Account"},
            {"id": "T1543", "name": "Create or Modify System Process"},
            {"id": "T1574", "name": "Hijack Execution Flow"},
            {"id": "T1562", "name": "Impair Defenses"},
            {"id": "T1505", "name": "Server Software Component"},
            {"id": "T1505.003", "name": "Server Software Component: Web Shell"},
            {"id": "T1053", "name": "Scheduled Task/Job"},
            {"id": "T1078", "name": "Valid Accounts"},
        ],
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "techniques": [
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
            {"id": "T1134", "name": "Access Token Manipulation"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1574", "name": "Hijack Execution Flow"},
            {"id": "T1055", "name": "Process Injection"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},
            {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
        ],
    },
    "Defense Evasion": {
        "id": "TA0005",
        "techniques": [
            {"id": "T1134", "name": "Access Token Manipulation"},
            {"id": "T1197", "name": "BITS Jobs"},
            {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
            {"id": "T1006", "name": "Direct Volume Access"},
            {"id": "T1070", "name": "Indicator Removal"},
            {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs"},
            {"id": "T1070.004", "name": "Indicator Removal: File Deletion"},
            {"id": "T1562", "name": "Impair Defenses"},
            {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
            {"id": "T1036", "name": "Masquerading"},
            {"id": "T1027", "name": "Obfuscated Files or Information"},
            {"id": "T1055", "name": "Process Injection"},
            {"id": "T1218", "name": "System Binary Proxy Execution"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1497", "name": "Virtualization/Sandbox Evasion"},
        ],
    },
    "Credential Access": {
        "id": "TA0006",
        "techniques": [
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
            {"id": "T1110.003", "name": "Brute Force: Password Spraying"},
            {"id": "T1555", "name": "Credentials from Password Stores"},
            {"id": "T1212", "name": "Exploitation for Credential Access"},
            {"id": "T1187", "name": "Forced Authentication"},
            {"id": "T1056", "name": "Input Capture"},
            {"id": "T1056.001", "name": "Input Capture: Keylogging"},
            {"id": "T1557", "name": "Adversary-in-the-Middle"},
            {"id": "T1040", "name": "Network Sniffing"},
            {"id": "T1003", "name": "OS Credential Dumping"},
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"},
            {"id": "T1528", "name": "Steal Application Access Token"},
            {"id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
            {"id": "T1539", "name": "Steal Web Session Cookie"},
        ],
    },
    "Discovery": {
        "id": "TA0007",
        "techniques": [
            {"id": "T1087", "name": "Account Discovery"},
            {"id": "T1010", "name": "Application Window Discovery"},
            {"id": "T1217", "name": "Browser Information Discovery"},
            {"id": "T1083", "name": "File and Directory Discovery"},
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1135", "name": "Network Share Discovery"},
            {"id": "T1040", "name": "Network Sniffing"},
            {"id": "T1201", "name": "Password Policy Discovery"},
            {"id": "T1069", "name": "Permission Groups Discovery"},
            {"id": "T1018", "name": "Remote System Discovery"},
            {"id": "T1518", "name": "Software Discovery"},
            {"id": "T1082", "name": "System Information Discovery"},
            {"id": "T1016", "name": "System Network Configuration Discovery"},
            {"id": "T1049", "name": "System Network Connections Discovery"},
            {"id": "T1033", "name": "System Owner/User Discovery"},
        ],
    },
    "Lateral Movement": {
        "id": "TA0008",
        "techniques": [
            {"id": "T1210", "name": "Exploitation of Remote Services"},
            {"id": "T1534", "name": "Internal Spearphishing"},
            {"id": "T1570", "name": "Lateral Tool Transfer"},
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
            {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
            {"id": "T1021.006", "name": "Remote Services: Windows Remote Management"},
            {"id": "T1091", "name": "Replication Through Removable Media"},
            {"id": "T1550", "name": "Use Alternate Authentication Material"},
            {"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"},
        ],
    },
    "Collection": {
        "id": "TA0009",
        "techniques": [
            {"id": "T1557", "name": "Adversary-in-the-Middle"},
            {"id": "T1560", "name": "Archive Collected Data"},
            {"id": "T1123", "name": "Audio Capture"},
            {"id": "T1119", "name": "Automated Collection"},
            {"id": "T1115", "name": "Clipboard Data"},
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1039", "name": "Data from Network Shared Drive"},
            {"id": "T1025", "name": "Data from Removable Media"},
            {"id": "T1074", "name": "Data Staged"},
            {"id": "T1114", "name": "Email Collection"},
            {"id": "T1056", "name": "Input Capture"},
            {"id": "T1113", "name": "Screen Capture"},
        ],
    },
    "Command and Control": {
        "id": "TA0011",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol"},
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
            {"id": "T1071.004", "name": "Application Layer Protocol: DNS"},
            {"id": "T1132", "name": "Data Encoding"},
            {"id": "T1001", "name": "Data Obfuscation"},
            {"id": "T1568", "name": "Dynamic Resolution"},
            {"id": "T1573", "name": "Encrypted Channel"},
            {"id": "T1008", "name": "Fallback Channels"},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
            {"id": "T1104", "name": "Multi-Stage Channels"},
            {"id": "T1095", "name": "Non-Application Layer Protocol"},
            {"id": "T1090", "name": "Proxy"},
            {"id": "T1219", "name": "Remote Access Software"},
        ],
    },
    "Exfiltration": {
        "id": "TA0010",
        "techniques": [
            {"id": "T1020", "name": "Automated Exfiltration"},
            {"id": "T1030", "name": "Data Transfer Size Limits"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1011", "name": "Exfiltration Over Other Network Medium"},
            {"id": "T1052", "name": "Exfiltration Over Physical Medium"},
            {"id": "T1567", "name": "Exfiltration Over Web Service"},
            {"id": "T1567.002", "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage"},
            {"id": "T1029", "name": "Scheduled Transfer"},
        ],
    },
    "Impact": {
        "id": "TA0040",
        "techniques": [
            {"id": "T1531", "name": "Account Access Removal"},
            {"id": "T1485", "name": "Data Destruction"},
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1565", "name": "Data Manipulation"},
            {"id": "T1491", "name": "Defacement"},
            {"id": "T1561", "name": "Disk Wipe"},
            {"id": "T1499", "name": "Endpoint Denial of Service"},
            {"id": "T1495", "name": "Firmware Corruption"},
            {"id": "T1490", "name": "Inhibit System Recovery"},
            {"id": "T1498", "name": "Network Denial of Service"},
            {"id": "T1496", "name": "Resource Hijacking"},
            {"id": "T1489", "name": "Service Stop"},
            {"id": "T1529", "name": "System Shutdown/Reboot"},
        ],
    },
}

DEFAULT_LOOKUP_VALUES = {
    # What kind of thing an asset is. Kept short enough to stay a real choice —
    # a vocabulary nobody can hold in their head gets "Other" every time, and an
    # aggregate over "Other" answers nothing.
    "asset_type": [
        "Server",
        "Workstation",
        "Laptop",
        "Mobile Device",
        "Virtual Machine",
        "Container / Pod",
        "Domain Controller",
        "Database",
        "Web Application",
        "SaaS Application",
        "Cloud Resource",
        "Network Device",
        "Security Appliance",
        "File Share / Storage",
        "Backup System",
        "User Account",
        "Service Account",
        "Mailbox",
        "OT / IoT Device",
        "Other",
    ],
    # Business criticality of the asset itself, independent of any one incident.
    # NULL means not assessed — there is no "Unknown" value here on purpose, so
    # that an unassessed asset cannot be mistaken for an assessed one.
    "asset_criticality": [
        "Critical",
        "High",
        "Moderate",
        "Low",
    ],
    # What an asset was *in a particular case* — lives on the case_assets link,
    # not on the asset. "Investigated - Not Affected" earns its place: recording
    # that a box was checked and found clean is a finding, and without somewhere
    # to put it that work disappears.
    "asset_role": [
        "Patient Zero",
        "Initially Compromised",
        "Lateral Movement Target",
        "Credential Source",
        "Data Source",
        "Exfiltration Path",
        "Command and Control",
        "Impacted / Degraded",
        "Investigated - Not Affected",
        "Other",
    ],
    "case_type": [
        "Ransomware",
        "Data Breach",
        "Phishing / BEC",
        "Malware Infection",
        "Insider Threat",
        "DDoS",
        "Unauthorized Access",
        "Vulnerability Exploitation",
        "Supply Chain Attack",
        "Identity Compromise",
        "Cloud Misconfiguration",
        "Other",
    ],
    "ioc_type": [
        "IP Address",
        "IPv6 Address",
        "Domain",
        "URL",
        "File Hash MD5",
        "File Hash SHA1",
        "File Hash SHA256",
        "Email Address",
        "Registry Key",
        "File Name/Path",
        "User Account",
        "Mutex",
        "CVE",
        "YARA Rule",
        "ASN",
        "Other",
    ],
    "evidence_type": [
        "Disk Image",
        "Memory Dump",
        "Log File",
        "Network Capture (PCAP)",
        "Email / PST",
        "Document",
        "Database Dump",
        "Malware Sample",
        "Screenshot",
        "Registry Hive",
        "Prefetch Files",
        "Browser Artifacts",
        "Cloud Storage Export",
        "Other",
    ],
}


DEFAULT_TIMELINE_CATEGORIES = [
    "Detection",
    "Investigation",
    "Containment",
    "Eradication",
    "Recovery",
    "Communication",
    "Attacker Action",
    "Other",
]

# Labels only — the hex value each slot renders as lives in TIMELINE_COLORS
# (app/models.py) and is not admin-editable, only the label is. Position
# here is the slot number (1-7); order matters.
DEFAULT_TIMELINE_COLOR_LABELS = [
    "Red",
    "Orange",
    "Amber",
    "Green",
    "Teal",
    "Blue",
    "Purple",
]


def _backfill_timeline_lookups(app):
    """
    Ensure timeline_category has its starter values and timeline_color has
    all 7 slots, without touching anything an admin already edited.

    Runs on every startup, not just when lookup_values is empty — case_type,
    ioc_type, and evidence_type were seeded once when this database was
    first created, but timeline_category and timeline_color are new lists
    added after that. On an existing install, LookupValue.query.count() == 0
    is already false by the time this runs, so the fresh-install seeding
    block above never touches them. This checks each new list on its own
    and only adds what's missing.
    """
    from app.models import db, LookupValue

    if LookupValue.query.filter_by(list_name="timeline_category").count() == 0:
        for i, value in enumerate(DEFAULT_TIMELINE_CATEGORIES):
            db.session.add(LookupValue(list_name="timeline_category", value=value, display_order=i))

    existing_slots = {
        lv.display_order
        for lv in LookupValue.query.filter_by(list_name="timeline_color").all()
    }
    for slot, label in enumerate(DEFAULT_TIMELINE_COLOR_LABELS, start=1):
        if slot not in existing_slots:
            db.session.add(LookupValue(list_name="timeline_color", value=label, display_order=slot))

    db.session.commit()


def _backfill_id_counters(app):
    """
    Initialise the ID counters from records that already exist.

    A database created before the counters were introduced already holds
    INC-0001..INC-00NN. Starting a fresh counter at zero would reissue those
    numbers and collide on the unique constraint, so the counter is seeded from
    the highest number actually in use. Runs once; afterwards the row exists and
    this is a no-op.
    """
    import re

    from app.models import db, Case, Evidence, IdCounter

    def _highest(model, column, prefix):
        best = 0
        pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
        for (value,) in db.session.query(column).all():
            if not value:
                continue
            m = pattern.match(value)
            if m:
                best = max(best, int(m.group(1)))
        return best

    for name, model, column, prefix_key, default_prefix in (
        ("case", Case, Case.case_id, "CASE_ID_PREFIX", "INC"),
        ("evidence", Evidence, Evidence.evidence_id, "EVIDENCE_ID_PREFIX", "EVD"),
    ):
        if db.session.get(IdCounter, name) is not None:
            continue
        prefix = app.config.get(prefix_key, default_prefix)
        start = _highest(model, column, prefix)
        db.session.add(IdCounter(name=name, last_value=start))
        if start:
            app.logger.info(
                "Initialised %s ID counter at %d from existing records", name, start
            )
    db.session.commit()


# Bootstrap admin passwords that must never reach a running deployment. The
# first entry shipped as the default in config.py and in .env.example, so it is
# the one most likely to be sitting in somebody's .env untouched.
_REJECTED_ADMIN_PASSWORDS = {
    "",
    "changeme123!",
    "changeme",
    "change-me",
    "password",
    "password123",
    "admin",
    "cairn",
}

# Matches users.MIN_PASSWORD_LENGTH — the bootstrap account should not be held
# to a lower standard than one created through the admin UI.
MIN_ADMIN_PASSWORD_LENGTH = 12


def seed_database(app):
    """Seed lookup values and create bootstrap admin if the database is empty."""
    import os

    from sqlalchemy import inspect

    from app.models import db, User, LookupValue

    with app.app_context():
        # When migrations are run as a separate deploy step (AUTO_UPGRADE_DB=false),
        # the schema may not exist yet on first boot. Skip rather than crash; the
        # next start seeds once `flask db upgrade` has run.
        inspector = inspect(db.engine)
        required = {"lookup_values", "users"}
        missing = required - set(inspector.get_table_names())
        if missing:
            app.logger.warning(
                "Skipping seed — tables not present yet: %s. "
                "Run 'flask db upgrade', then restart.", ", ".join(sorted(missing)),
            )
            return

        _backfill_id_counters(app)
        _backfill_timeline_lookups(app)

        # Seed each list on its own, not the whole table at once.
        #
        # This was gated on LookupValue.query.count() == 0 — seed everything only
        # if the table is empty — and that gate was broken by the line directly
        # above it. _backfill_timeline_lookups() commits timeline_category and
        # timeline_color first, so on a fresh install the table was never empty by
        # the time this ran, and case_type, ioc_type and evidence_type were never
        # seeded at all.
        #
        # Verified against an empty database before this change: a brand new
        # deployment came up with only the two timeline lists, and empty Case Type,
        # IOC Type and Evidence Type dropdowns. Any install older than the timeline
        # work already had those values and so never saw it, which is why it sat
        # here unnoticed.
        #
        # Per-list is also what every list added from here on needs, for exactly
        # the reason _backfill_timeline_lookups() already documents. A list an
        # admin has emptied on purpose will be re-seeded; that matches the
        # behaviour of the timeline backfill and is the lesser of the two wrongs.
        for list_name, values in DEFAULT_LOOKUP_VALUES.items():
            if LookupValue.query.filter_by(list_name=list_name).count():
                continue
            # display_order restarts per list. It always should have — the column
            # is only ever read within one list_name.
            for order, value in enumerate(values):
                db.session.add(
                    LookupValue(list_name=list_name, value=value, display_order=order)
                )
        db.session.commit()

        # Create bootstrap admin if no users exist
        if User.query.count() == 0:
            from flask import current_app as c_app

            # Login lowercases the submitted username, so the seeded value must be
            # lowercased too. An ADMIN_USERNAME with a capital letter used to create
            # an account that nobody could sign in to.
            username = c_app.config["ADMIN_USERNAME"].strip().lower()
            password = c_app.config["ADMIN_PASSWORD"]

            if not username:
                raise RuntimeError("ADMIN_USERNAME must be set to bootstrap the first admin.")

            # Refuse to create the first admin with a placeholder.
            #
            # This is the account that can download the entire database and
            # restore over it. A guessable password on it is not a weak password,
            # it is the whole compromise. SECRET_KEY and DATABASE_URL already
            # refuse to start on a placeholder for the same reason (see
            # app/config.py); this closes the one that was left with a working
            # default and a log line.
            #
            # Only reached when there are no users at all, so an existing
            # deployment is unaffected.
            if (password.strip().lower() in _REJECTED_ADMIN_PASSWORDS
                    or len(password) < MIN_ADMIN_PASSWORD_LENGTH):
                if os.environ.get("ALLOW_INSECURE_ADMIN_PASSWORD", "").lower() != "true":
                    raise RuntimeError(
                        "Refusing to create the bootstrap admin account: "
                        "ADMIN_PASSWORD is unset, a known placeholder, or shorter "
                        f"than {MIN_ADMIN_PASSWORD_LENGTH} characters.\n\n"
                        "This account can download and overwrite the whole "
                        "database. Set ADMIN_PASSWORD in .env to something "
                        "generated, e.g.:\n"
                        "  openssl rand -base64 24\n\n"
                        "For local development only, set "
                        "ALLOW_INSECURE_ADMIN_PASSWORD=true."
                    )
                c_app.logger.warning(
                    "Bootstrap admin '%s' created with a weak password because "
                    "ALLOW_INSECURE_ADMIN_PASSWORD=true. Never set that outside "
                    "local development.", username,
                )

            u = User(
                username=username,
                email=c_app.config["ADMIN_EMAIL"].strip().lower(),
                name=c_app.config["ADMIN_NAME"],
                role="admin",
                is_active=True,
            )
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            c_app.logger.info("Bootstrap admin '%s' created.", username)
