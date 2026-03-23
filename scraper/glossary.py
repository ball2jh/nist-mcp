"""Scraper for NIST glossary terms and definitions.

Attempts to download the NIST CSRC glossary as JSON.  Falls back to a curated
set of the most important cybersecurity terms when the endpoint is
unreachable.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS glossary (
    term       TEXT PRIMARY KEY,
    definition TEXT NOT NULL,
    source     TEXT,
    see_also   TEXT
);
CREATE INDEX IF NOT EXISTS idx_glossary_term ON glossary(term);
"""

# ---------------------------------------------------------------------------
# Data source
# ---------------------------------------------------------------------------

# NIST CSRC glossary API endpoint
_GLOSSARY_URL = "https://csrc.nist.gov/glossary/export/json"
_TIMEOUT = 90

# ---------------------------------------------------------------------------
# Fallback: curated glossary of key NIST / cybersecurity terms
# ---------------------------------------------------------------------------

_CURATED_TERMS: list[dict[str, str]] = [
    {"term": "Access Control", "definition": "The process of granting or denying specific requests to: 1) obtain and use information and related information processing services; and 2) enter specific physical facilities.", "source": "SP 800-53"},
    {"term": "Advanced Persistent Threat", "definition": "An adversary that possesses sophisticated levels of expertise and significant resources which allow it to create opportunities to achieve its objectives by using multiple attack vectors.", "source": "SP 800-39"},
    {"term": "Assessment", "definition": "The testing or evaluation of security controls to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome.", "source": "SP 800-53A"},
    {"term": "Audit", "definition": "Independent review and examination of records and activities to assess the adequacy of system controls, to ensure compliance with established policies and operational procedures.", "source": "SP 800-53"},
    {"term": "Authentication", "definition": "Verifying the identity of a user, process, or device, often as a prerequisite to allowing access to resources in an information system.", "source": "FIPS 200"},
    {"term": "Authorization", "definition": "Access privileges granted to a user, program, or process or the act of granting those privileges.", "source": "SP 800-53"},
    {"term": "Availability", "definition": "Ensuring timely and reliable access to and use of information.", "source": "FIPS 199"},
    {"term": "Baseline", "definition": "A set of security controls that provides a starting point for the tailoring process.", "source": "SP 800-53"},
    {"term": "Boundary Protection", "definition": "Monitoring and control of communications at the external boundary of an information system to prevent and detect malicious and other unauthorized communications.", "source": "SP 800-53"},
    {"term": "Certificate Authority", "definition": "A trusted entity that issues and revokes public key certificates.", "source": "SP 800-32"},
    {"term": "Common Vulnerabilities and Exposures", "definition": "A dictionary of common names for publicly known information system vulnerabilities.", "source": "NIST"},
    {"term": "Confidentiality", "definition": "Preserving authorized restrictions on information access and disclosure, including means for protecting personal privacy and proprietary information.", "source": "FIPS 199"},
    {"term": "Configuration Management", "definition": "A collection of activities focused on establishing and maintaining the integrity of information technology products and information systems, through control of processes for initializing, changing, and monitoring the configurations of those products and systems throughout the system development life cycle.", "source": "SP 800-128"},
    {"term": "Continuous Monitoring", "definition": "Maintaining ongoing awareness of information security, vulnerabilities, and threats to support organizational risk management decisions.", "source": "SP 800-137"},
    {"term": "Control", "definition": "A safeguard or countermeasure prescribed for an information system or an organization designed to protect the confidentiality, integrity, and availability of its information and to meet a set of defined security requirements.", "source": "SP 800-53"},
    {"term": "Cybersecurity", "definition": "Prevention of damage to, protection of, and restoration of computers, electronic communications systems, electronic communications services, wire communication, and electronic communication, including information contained therein, to ensure its availability, integrity, authentication, confidentiality, and nonrepudiation.", "source": "NIST CSF"},
    {"term": "Cybersecurity Framework", "definition": "A voluntary framework that consists of standards, guidelines, and best practices to manage cybersecurity-related risk.", "source": "NIST CSF"},
    {"term": "Data Loss Prevention", "definition": "A set of tools and processes used to ensure that sensitive data is not lost, misused, or accessed by unauthorized users.", "source": "NIST"},
    {"term": "Denial of Service", "definition": "The prevention of authorized access to resources or the delaying of time-critical operations.", "source": "SP 800-53"},
    {"term": "Digital Signature", "definition": "The result of a cryptographic transformation of data that, when properly implemented, provides a mechanism for verifying origin authentication, data integrity, and signatory non-repudiation.", "source": "FIPS 186"},
    {"term": "Encryption", "definition": "The process of transforming plaintext into ciphertext.", "source": "SP 800-53"},
    {"term": "Federal Information Processing Standard", "definition": "A standard for adoption and use by federal departments and agencies that has been developed within the Information Technology Laboratory and published by NIST.", "source": "FIPS"},
    {"term": "FIPS 199", "definition": "Standards for Security Categorization of Federal Information and Information Systems.", "source": "FIPS 199"},
    {"term": "FIPS 200", "definition": "Minimum Security Requirements for Federal Information and Information Systems.", "source": "FIPS 200"},
    {"term": "Firewall", "definition": "A device or program that controls the flow of network traffic between networks or hosts that employ differing security postures.", "source": "SP 800-41"},
    {"term": "Identification", "definition": "The process of verifying the identity of a user, process, or device, usually as a prerequisite for granting access to resources.", "source": "FIPS 201"},
    {"term": "Impact", "definition": "The magnitude of harm that can be expected to result from the consequences of unauthorized disclosure of information, unauthorized modification of information, unauthorized destruction of information, or loss of information or information system availability.", "source": "FIPS 199"},
    {"term": "Incident", "definition": "An occurrence that actually or potentially jeopardizes the confidentiality, integrity, or availability of an information system or the information the system processes, stores, or transmits or that constitutes a violation or imminent threat of violation of security policies, security procedures, or acceptable use policies.", "source": "SP 800-61"},
    {"term": "Incident Response", "definition": "The mitigation of violations of security policies and recommended practices.", "source": "SP 800-61"},
    {"term": "Information Security", "definition": "The protection of information and information systems from unauthorized access, use, disclosure, disruption, modification, or destruction in order to provide confidentiality, integrity, and availability.", "source": "FIPS 199"},
    {"term": "Integrity", "definition": "Guarding against improper information modification or destruction, and includes ensuring information non-repudiation and authenticity.", "source": "FIPS 199"},
    {"term": "Intrusion Detection System", "definition": "A security service that monitors and analyzes network or system events for the purpose of finding, and providing real-time or near real-time warning of, attempts to access system resources in an unauthorized manner.", "source": "SP 800-94"},
    {"term": "Key Management", "definition": "The activities involving the handling of cryptographic keys and other related security parameters during the entire life cycle of the keys.", "source": "SP 800-57"},
    {"term": "Least Privilege", "definition": "The principle that a security architecture should be designed so that each entity is granted the minimum system resources and authorizations that the entity needs to perform its function.", "source": "SP 800-53"},
    {"term": "Malicious Code", "definition": "Software or firmware intended to perform an unauthorized process that will have adverse impact on the confidentiality, integrity, or availability of an information system.", "source": "SP 800-53"},
    {"term": "Multi-Factor Authentication", "definition": "Authentication using two or more factors to achieve authentication. Factors include: (i) something you know (e.g., password/PIN); (ii) something you have (e.g., cryptographic identification device, token); or (iii) something you are (e.g., biometric).", "source": "SP 800-63"},
    {"term": "Non-Repudiation", "definition": "Assurance that the sender of information is provided with proof of delivery and the recipient is provided with proof of the sender's identity, so neither can later deny having processed the information.", "source": "SP 800-53"},
    {"term": "OSCAL", "definition": "Open Security Controls Assessment Language. A set of standardized, machine-readable formats for publishing, implementing, and assessing security controls.", "source": "NIST"},
    {"term": "Patch Management", "definition": "The systematic notification, identification, deployment, installation, and verification of operating system and application software code revisions.", "source": "SP 800-40"},
    {"term": "Penetration Testing", "definition": "A method of testing where testers target individual binary components or the application as a whole to determine whether intra or intercomponent vulnerabilities can be exploited to compromise the application, its data, or its environment resources.", "source": "SP 800-115"},
    {"term": "Personally Identifiable Information", "definition": "Information that can be used to distinguish or trace an individual's identity, either alone or when combined with other information that is linked or linkable to a specific individual.", "source": "SP 800-122"},
    {"term": "Phishing", "definition": "A technique for attempting to acquire sensitive data, such as bank account numbers, through a fraudulent solicitation in email or on a web site, in which the perpetrator masquerades as a legitimate business or reputable person.", "source": "SP 800-83"},
    {"term": "Plan of Action and Milestones", "definition": "A document that identifies tasks needing to be accomplished. It details resources required to accomplish the elements of the plan, any milestones in meeting the tasks, and scheduled completion dates for the milestones.", "source": "SP 800-53"},
    {"term": "Public Key Infrastructure", "definition": "A set of policies, processes, server platforms, software and workstations used for the purpose of administering certificates and public-private key pairs, including the ability to issue, maintain, and revoke public key certificates.", "source": "SP 800-32"},
    {"term": "Ransomware", "definition": "A type of malicious software designed to block access to a computer system or data, often by encrypting data or programs, until a sum of money is paid.", "source": "NIST"},
    {"term": "Risk", "definition": "A measure of the extent to which an entity is threatened by a potential circumstance or event, and typically a function of: (i) the adverse impacts that would arise if the circumstance or event occurs; and (ii) the likelihood of occurrence.", "source": "SP 800-30"},
    {"term": "Risk Assessment", "definition": "The process of identifying risks to organizational operations, organizational assets, individuals, other organizations, and the Nation, resulting from the operation of an information system.", "source": "SP 800-30"},
    {"term": "Risk Management", "definition": "The program and supporting processes to manage information security risk to organizational operations, organizational assets, individuals, other organizations, and the Nation, and includes: (i) establishing the context for risk-related activities; (ii) assessing risk; (iii) responding to risk once determined; and (iv) monitoring risk on an ongoing basis.", "source": "SP 800-39"},
    {"term": "Security Categorization", "definition": "The process of determining the security category for information or an information system, based on the potential impact of a loss of confidentiality, integrity, or availability.", "source": "FIPS 199"},
    {"term": "Security Control", "definition": "The safeguards or countermeasures prescribed for an information system or an organization to protect the confidentiality, integrity, and availability of the system and its information.", "source": "SP 800-53"},
    {"term": "Social Engineering", "definition": "An attempt to trick someone into revealing information (e.g., a password) that can be used to attack systems or networks.", "source": "SP 800-61"},
    {"term": "Supply Chain Risk Management", "definition": "The process of identifying, assessing, and mitigating the risks associated with the distributed and interconnected nature of information technology product and service supply chains.", "source": "SP 800-161"},
    {"term": "System Security Plan", "definition": "Formal document that provides an overview of the security requirements for an information system and describes the security controls in place or planned for meeting those requirements.", "source": "SP 800-18"},
    {"term": "Threat", "definition": "Any circumstance or event with the potential to adversely impact organizational operations, organizational assets, individuals, other organizations, or the Nation through an information system via unauthorized access, destruction, disclosure, modification of information, and/or denial of service.", "source": "SP 800-30"},
    {"term": "Two-Factor Authentication", "definition": "Authentication using two different factors: something you know, something you have, or something you are.", "source": "SP 800-63"},
    {"term": "Vulnerability", "definition": "Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source.", "source": "SP 800-30"},
    {"term": "Vulnerability Assessment", "definition": "Systematic examination of an information system or product to determine the adequacy of security measures, identify security deficiencies, provide data from which to predict the effectiveness of proposed security measures, and confirm the adequacy of such measures after implementation.", "source": "SP 800-53A"},
    {"term": "Zero Trust", "definition": "A security model based on the principle that organizations should not automatically trust anything inside or outside its perimeters and instead must verify anything and everything trying to connect to its systems before granting access.", "source": "SP 800-207"},
    {"term": "Zero Trust Architecture", "definition": "An enterprise cybersecurity architecture that is based on zero trust principles and designed to prevent data breaches and limit internal lateral movement.", "source": "SP 800-207"},
]


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------


def _parse_glossary_json(data: dict[str, Any]) -> list[dict[str, str]]:
    """Parse the NIST CSRC glossary JSON export into row dicts.

    The exact JSON structure varies; we handle known shapes:
    - Top-level list of term objects
    - Wrapped in { "glossaryTerms": [...] } or { "data": [...] }
    """
    terms_list: list[dict[str, Any]] | None = None

    if isinstance(data, list):
        terms_list = data
    elif isinstance(data, dict):
        for key in ("glossaryTerms", "data", "terms", "results"):
            if key in data and isinstance(data[key], list):
                terms_list = data[key]
                break
        # Maybe the dict itself is a mapping of term -> definition
        if terms_list is None and all(isinstance(v, str) for v in data.values()):
            return [
                {"term": k, "definition": v, "source": "NIST Glossary", "see_also": ""}
                for k, v in data.items()
            ]

    if not terms_list:
        return []

    rows: list[dict[str, str]] = []
    for item in terms_list:
        if not isinstance(item, dict):
            continue

        # Try multiple field-name conventions
        term = (
            item.get("term")
            or item.get("name")
            or item.get("title")
            or ""
        )
        definition = (
            item.get("definition")
            or item.get("text")
            or item.get("description")
            or ""
        )
        # Handle definitions that are lists of paragraphs
        if isinstance(definition, list):
            # Each entry might be a dict with "text" key or a plain string
            parts = []
            for d in definition:
                if isinstance(d, dict):
                    parts.append(d.get("text", str(d)))
                else:
                    parts.append(str(d))
            definition = " ".join(parts)

        source = item.get("source", item.get("sources", "NIST Glossary"))
        if isinstance(source, list):
            source = "; ".join(str(s) for s in source)

        see_also = item.get("seeAlso", item.get("see_also", ""))
        if isinstance(see_also, list):
            see_also = ", ".join(str(s) for s in see_also)

        if term and definition:
            rows.append({
                "term": str(term).strip(),
                "definition": str(definition).strip(),
                "source": str(source).strip() if source else "",
                "see_also": str(see_also).strip() if see_also else "",
            })

    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrape_glossary(db: sqlite3.Connection) -> int:
    """Download NIST glossary and populate the ``glossary`` table.

    Falls back to curated terms if the JSON endpoint is unreachable.
    Returns the number of rows inserted.
    """
    rows: list[dict[str, str]] | None = None

    try:
        log.info("Downloading NIST glossary from %s ...", _GLOSSARY_URL)
        client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        resp = client.get(_GLOSSARY_URL)
        resp.raise_for_status()
        client.close()

        data = resp.json()
        rows = _parse_glossary_json(data)
        if rows:
            log.info("Parsed %d glossary terms from NIST API", len(rows))
        else:
            log.warning("Glossary JSON parsed but no terms extracted; falling back")
            rows = None
    except Exception:
        log.warning("Glossary download failed; using curated terms", exc_info=True)

    if rows is None:
        rows = [
            {
                "term": t["term"],
                "definition": t["definition"],
                "source": t.get("source", ""),
                "see_also": t.get("see_also", ""),
            }
            for t in _CURATED_TERMS
        ]
        log.info("Using curated glossary: %d terms", len(rows))

    # Insert
    db.execute("DELETE FROM glossary")
    db.executemany(
        """
        INSERT OR REPLACE INTO glossary (term, definition, source, see_also)
        VALUES (:term, :definition, :source, :see_also)
        """,
        rows,
    )
    db.commit()
    log.info("Inserted %d glossary terms", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = scrape_glossary(conn)
    print(f"Inserted {n} glossary terms")

    cur = conn.execute("SELECT term, substr(definition, 1, 60) FROM glossary LIMIT 10")
    for row in cur:
        print(f"  {row[0]}: {row[1]}...")
    conn.close()
