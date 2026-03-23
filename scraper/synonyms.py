"""Builder for search synonym mappings across NIST terminology.

This is NOT a scraper -- it is a hardcoded table of ~200 security term
synonyms and aliases that map common abbreviations, vendor jargon, and
everyday language to the canonical terminology used in NIST publications
(especially SP 800-53 control language).
"""

from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS synonyms (
    alias    TEXT NOT NULL,
    canonical TEXT NOT NULL,
    PRIMARY KEY (alias, canonical)
);
CREATE INDEX IF NOT EXISTS idx_syn_alias ON synonyms(alias);
CREATE INDEX IF NOT EXISTS idx_syn_canonical ON synonyms(canonical);
"""

# ---------------------------------------------------------------------------
# Curated synonym table
#
# Each tuple is (alias, canonical_term).  The alias is what a user might type;
# the canonical term is the standard NIST / security vocabulary form.
# ---------------------------------------------------------------------------

SYNONYMS: list[tuple[str, str]] = [
    # --- Common abbreviations -> full names --------------------------------
    ("MFA", "multi-factor authentication"),
    ("2FA", "multi-factor authentication"),
    ("RBAC", "role-based access control"),
    ("ABAC", "attribute-based access control"),
    ("SSO", "single sign-on"),
    ("VPN", "virtual private network"),
    ("IDS", "intrusion detection system"),
    ("IPS", "intrusion prevention system"),
    ("WAF", "web application firewall"),
    ("DLP", "data loss prevention"),
    ("SIEM", "security information and event management"),
    ("SOC", "security operations center"),
    ("NOC", "network operations center"),
    ("PKI", "public key infrastructure"),
    ("CA", "certificate authority"),
    ("RA", "registration authority"),
    ("CRL", "certificate revocation list"),
    ("OCSP", "online certificate status protocol"),
    ("TLS", "transport layer security"),
    ("SSL", "transport layer security"),
    ("AES", "advanced encryption standard"),
    ("RSA", "asymmetric encryption"),
    ("ECC", "elliptic curve cryptography"),
    ("SHA", "secure hash algorithm"),
    ("HMAC", "hash-based message authentication code"),
    ("KDF", "key derivation function"),
    ("HSM", "hardware security module"),
    ("TPM", "trusted platform module"),
    ("NAC", "network access control"),
    ("IAM", "identity and access management"),
    ("PAM", "privileged access management"),
    ("CASB", "cloud access security broker"),
    ("EDR", "endpoint detection and response"),
    ("XDR", "extended detection and response"),
    ("MDR", "managed detection and response"),
    ("SOAR", "security orchestration automation and response"),
    ("UEBA", "user and entity behavior analytics"),
    ("CWPP", "cloud workload protection platform"),
    ("CSPM", "cloud security posture management"),
    ("CNAPP", "cloud-native application protection platform"),
    ("ZTNA", "zero trust network access"),
    ("SASE", "secure access service edge"),
    ("SWG", "secure web gateway"),
    ("DNS", "domain name system"),
    ("DNSSEC", "domain name system security extensions"),
    ("DKIM", "domainkeys identified mail"),
    ("DMARC", "domain-based message authentication reporting and conformance"),
    ("SPF", "sender policy framework"),
    ("LDAP", "lightweight directory access protocol"),
    ("SAML", "security assertion markup language"),
    ("OIDC", "openid connect"),
    ("OAuth", "open authorization"),
    ("JWT", "json web token"),
    ("API", "application programming interface"),
    ("REST", "representational state transfer"),

    # --- NIST-specific terms and standards ---------------------------------
    ("FIPS", "federal information processing standard"),
    ("FedRAMP", "federal risk and authorization management program"),
    ("FISMA", "federal information security modernization act"),
    ("OSCAL", "open security controls assessment language"),
    ("SCAP", "security content automation protocol"),
    ("XCCDF", "extensible configuration checklist description format"),
    ("OVAL", "open vulnerability and assessment language"),
    ("CPE", "common platform enumeration"),
    ("CVE", "common vulnerabilities and exposures"),
    ("CVSS", "common vulnerability scoring system"),
    ("CWE", "common weakness enumeration"),
    ("NVD", "national vulnerability database"),
    ("CCE", "common configuration enumeration"),
    ("SWID", "software identification tag"),
    ("SBOM", "software bill of materials"),
    ("RMF", "risk management framework"),
    ("CSF", "cybersecurity framework"),
    ("NIST CSF", "cybersecurity framework"),
    ("SP 800-53", "security and privacy controls"),
    ("800-53", "security and privacy controls"),
    ("SP 800-171", "protecting controlled unclassified information"),
    ("800-171", "protecting controlled unclassified information"),
    ("CUI", "controlled unclassified information"),
    ("CMMC", "cybersecurity maturity model certification"),
    ("FCI", "federal contract information"),
    ("ATO", "authority to operate"),
    ("P-ATO", "provisional authority to operate"),
    ("POA&M", "plan of action and milestones"),
    ("POAM", "plan of action and milestones"),
    ("SSP", "system security plan"),
    ("BIA", "business impact analysis"),
    ("BCP", "business continuity plan"),
    ("DRP", "disaster recovery plan"),
    ("COOP", "continuity of operations plan"),
    ("CONOPS", "concept of operations"),

    # --- Compliance standards and frameworks --------------------------------
    ("PII", "personally identifiable information"),
    ("PHI", "protected health information"),
    ("HIPAA", "health insurance portability and accountability act"),
    ("PCI DSS", "payment card industry data security standard"),
    ("PCI", "payment card industry data security standard"),
    ("SOX", "sarbanes-oxley act"),
    ("GDPR", "general data protection regulation"),
    ("CCPA", "california consumer privacy act"),
    ("GLBA", "gramm-leach-bliley act"),
    ("FERPA", "family educational rights and privacy act"),
    ("COPPA", "children's online privacy protection act"),
    ("SOC 2", "service organization control type 2"),
    ("SOC2", "service organization control type 2"),
    ("ISO 27001", "information security management system standard"),
    ("ISO 27002", "information security controls standard"),
    ("ISO 27005", "information security risk management standard"),
    ("COBIT", "control objectives for information and related technologies"),
    ("ITIL", "information technology infrastructure library"),
    ("CIS Controls", "center for internet security controls"),
    ("CIS Benchmarks", "center for internet security benchmarks"),
    ("MITRE ATT&CK", "adversarial tactics techniques and common knowledge"),
    ("ATT&CK", "adversarial tactics techniques and common knowledge"),
    ("STIX", "structured threat information expression"),
    ("TAXII", "trusted automated exchange of intelligence information"),

    # --- Common security concepts -> NIST control language -----------------
    ("firewall", "boundary protection"),
    ("router ACL", "boundary protection"),
    ("network segmentation", "boundary protection"),
    ("microsegmentation", "boundary protection"),
    ("DMZ", "boundary protection"),
    ("demilitarized zone", "boundary protection"),
    ("encryption at rest", "data at rest protection"),
    ("disk encryption", "data at rest protection"),
    ("full disk encryption", "data at rest protection"),
    ("FDE", "data at rest protection"),
    ("encryption in transit", "data in transit protection"),
    ("password", "authenticator"),
    ("passphrase", "authenticator"),
    ("credential", "authenticator"),
    ("biometric", "authenticator"),
    ("token", "authenticator"),
    ("smart card", "authenticator"),
    ("PIV", "personal identity verification"),
    ("CAC", "common access card"),
    ("antivirus", "malicious code protection"),
    ("anti-malware", "malicious code protection"),
    ("antimalware", "malicious code protection"),
    ("endpoint protection", "malicious code protection"),
    ("ransomware", "malicious code"),
    ("malware", "malicious code"),
    ("trojan", "malicious code"),
    ("worm", "malicious code"),
    ("virus", "malicious code"),
    ("spyware", "malicious code"),
    ("rootkit", "malicious code"),
    ("phishing", "social engineering"),
    ("spear phishing", "social engineering"),
    ("vishing", "social engineering"),
    ("smishing", "social engineering"),
    ("pretexting", "social engineering"),
    ("whaling", "social engineering"),
    ("APT", "advanced persistent threat"),
    ("zero-day", "vulnerability"),
    ("0-day", "vulnerability"),
    ("exploit", "vulnerability exploitation"),
    ("pentest", "penetration testing"),
    ("pen test", "penetration testing"),
    ("red team", "penetration testing"),
    ("vuln scan", "vulnerability scanning"),
    ("vulnerability scan", "vulnerability scanning"),
    ("patch", "flaw remediation"),
    ("patching", "flaw remediation"),
    ("patch management", "flaw remediation"),
    ("hotfix", "flaw remediation"),
    ("security update", "flaw remediation"),
    ("hardening", "configuration management"),
    ("system hardening", "configuration management"),
    ("baseline configuration", "configuration management"),
    ("golden image", "configuration management"),
    ("least privilege", "least privilege"),
    ("need to know", "least privilege"),
    ("separation of duties", "separation of duties"),
    ("SoD", "separation of duties"),
    ("dual control", "separation of duties"),
    ("two-person rule", "separation of duties"),
    ("audit log", "audit and accountability"),
    ("audit trail", "audit and accountability"),
    ("logging", "audit and accountability"),
    ("log management", "audit and accountability"),
    ("event logging", "audit and accountability"),
    ("SYSLOG", "audit and accountability"),
    ("backup", "system backup"),
    ("data backup", "system backup"),
    ("disaster recovery", "contingency planning"),
    ("DR", "contingency planning"),
    ("failover", "contingency planning"),
    ("high availability", "contingency planning"),
    ("HA", "contingency planning"),
    ("incident response", "incident handling"),
    ("IR", "incident handling"),
    ("CSIRT", "incident handling"),
    ("CERT", "incident handling"),
    ("security awareness", "awareness and training"),
    ("security training", "awareness and training"),
    ("phishing training", "awareness and training"),
    ("change management", "configuration change control"),
    ("change control", "configuration change control"),
    ("CAB", "configuration change control"),
    ("whitelist", "allow list"),
    ("allowlist", "allow list"),
    ("blacklist", "deny list"),
    ("blocklist", "deny list"),
    ("denylist", "deny list"),
    ("sandbox", "application isolation"),
    ("containerization", "application isolation"),
    ("air gap", "network disconnection"),
    ("airgap", "network disconnection"),
    ("honeypot", "deception"),
    ("honeynet", "deception"),

    # --- Zero trust terminology -------------------------------------------
    ("zero trust", "zero trust architecture"),
    ("ZTA", "zero trust architecture"),
    ("ZT", "zero trust architecture"),
    ("BeyondCorp", "zero trust architecture"),
    ("software-defined perimeter", "zero trust architecture"),
    ("SDP", "zero trust architecture"),

    # --- Cloud security ---------------------------------------------------
    ("IaaS", "infrastructure as a service"),
    ("PaaS", "platform as a service"),
    ("SaaS", "software as a service"),
    ("shared responsibility", "shared responsibility model"),
    ("cloud security", "cloud computing security"),
    ("serverless", "cloud computing"),
    ("container security", "cloud computing security"),
    ("DevSecOps", "secure development life cycle"),
    ("SDLC", "system development life cycle"),
    ("CI/CD", "continuous integration continuous delivery"),
    ("shift left", "secure development life cycle"),
    ("SAST", "static application security testing"),
    ("DAST", "dynamic application security testing"),
    ("IAST", "interactive application security testing"),
    ("SCA", "software composition analysis"),
    ("code review", "secure code review"),

    # --- Privacy ----------------------------------------------------------
    ("privacy impact assessment", "privacy impact assessment"),
    ("PIA", "privacy impact assessment"),
    ("DPIA", "data protection impact assessment"),
    ("data minimization", "data minimization"),
    ("data retention", "data retention"),
    ("data classification", "information classification"),
    ("data labeling", "information classification"),
    ("DPO", "data protection officer"),

    # --- Governance -------------------------------------------------------
    ("GRC", "governance risk and compliance"),
    ("KRI", "key risk indicator"),
    ("KPI", "key performance indicator"),
    ("SLA", "service level agreement"),
    ("OLA", "operational level agreement"),
    ("MOU", "memorandum of understanding"),
    ("MOA", "memorandum of agreement"),
    ("ISA", "interconnection security agreement"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_synonyms(db: sqlite3.Connection) -> int:
    """Populate the ``synonyms`` table with curated term mappings.

    Returns the number of rows inserted.
    """
    db.execute("DELETE FROM synonyms")
    db.executemany(
        "INSERT INTO synonyms (alias, canonical) VALUES (?, ?)",
        SYNONYMS,
    )
    db.commit()
    log.info("Inserted %d synonym mappings", len(SYNONYMS))
    return len(SYNONYMS)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = build_synonyms(conn)
    print(f"Inserted {n} synonym mappings")

    # Show some examples
    cur = conn.execute("SELECT alias, canonical FROM synonyms LIMIT 15")
    for row in cur:
        print(f"  {row[0]:30s} -> {row[1]}")

    # Check uniqueness
    cur = conn.execute(
        "SELECT COUNT(DISTINCT alias) as aliases, COUNT(DISTINCT canonical) as canonicals FROM synonyms"
    )
    row = cur.fetchone()
    print(f"Unique aliases: {row[0]}, Unique canonical terms: {row[1]}")
    conn.close()
