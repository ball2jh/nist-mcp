"""Scraper for NICE Cybersecurity Workforce Framework data.

The NICE Framework (SP 800-181 Rev. 1) defines work roles for the
cybersecurity workforce.  This module provides a hardcoded reference dataset
of categories and work roles from NICE Framework v2.1, since the canonical
source (NICCS / NIST) does not expose a stable machine-readable download.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nice_roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT,
    knowledge   TEXT,
    skills      TEXT,
    tasks       TEXT
);
CREATE INDEX IF NOT EXISTS idx_nice_category ON nice_roles(category);
CREATE VIRTUAL TABLE IF NOT EXISTS nice_roles_fts USING fts5(
    id, name, category, description,
    content=nice_roles, content_rowid=rowid
);
"""

# ---------------------------------------------------------------------------
# NICE Framework reference data (SP 800-181r1 / NICE Framework v2.1)
# ---------------------------------------------------------------------------

# 7 categories
_CATEGORIES: list[dict[str, str]] = [
    {
        "id": "SP",
        "name": "Securely Provision",
        "category": "Securely Provision",
        "description": "Conceptualizes, designs, procures, and/or builds secure information technology (IT) systems, with responsibility for aspects of system and/or network development.",
    },
    {
        "id": "OM",
        "name": "Operate and Maintain",
        "category": "Operate and Maintain",
        "description": "Provides the support, administration, and maintenance necessary to ensure effective and efficient information technology (IT) system performance and security.",
    },
    {
        "id": "OV",
        "name": "Oversee and Govern",
        "category": "Oversee and Govern",
        "description": "Provides leadership, management, direction, or development and advocacy so the organization may effectively conduct cybersecurity work.",
    },
    {
        "id": "PR",
        "name": "Protect and Defend",
        "category": "Protect and Defend",
        "description": "Identifies, analyzes, and mitigates threats to internal information technology (IT) systems and/or networks.",
    },
    {
        "id": "AN",
        "name": "Analyze",
        "category": "Analyze",
        "description": "Performs highly-specialized review and evaluation of incoming cybersecurity information to determine its usefulness for intelligence.",
    },
    {
        "id": "CO",
        "name": "Collect and Operate",
        "category": "Collect and Operate",
        "description": "Provides specialized denial and deception operations and collection of cybersecurity information that may be used to develop intelligence.",
    },
    {
        "id": "IN",
        "name": "Investigate",
        "category": "Investigate",
        "description": "Investigates cybersecurity events or crimes related to information technology (IT) systems, networks, and digital evidence.",
    },
]

# Work roles organized by category
_WORK_ROLES: list[dict[str, str]] = [
    # Securely Provision (SP)
    {
        "id": "SP-RSK-001",
        "name": "Authorizing Official/Designating Representative",
        "category": "Securely Provision",
        "description": "Senior official or executive with the authority to formally assume responsibility for operating an information system at an acceptable level of risk to organizational operations and assets, individuals, other organizations, and the Nation.",
    },
    {
        "id": "SP-RSK-002",
        "name": "Security Control Assessor",
        "category": "Securely Provision",
        "description": "Conducts independent comprehensive assessments of the management, operational, and technical security controls and control enhancements employed within or inherited by an information technology (IT) system to determine the overall effectiveness of the controls.",
    },
    {
        "id": "SP-DEV-001",
        "name": "Software Developer",
        "category": "Securely Provision",
        "description": "Develops, creates, maintains, and writes/codes new (or modifies existing) computer applications, software, or specialized utility programs following software assurance best practices.",
    },
    {
        "id": "SP-DEV-002",
        "name": "Secure Software Assessor",
        "category": "Securely Provision",
        "description": "Analyzes the security of new or existing computer applications, software, or specialized utility programs and provides actionable results.",
    },
    {
        "id": "SP-ARC-001",
        "name": "Enterprise Architect",
        "category": "Securely Provision",
        "description": "Develops and maintains business, systems, and information processes to support enterprise mission needs; develops information technology (IT) rules and requirements that describe baseline and target architectures.",
    },
    {
        "id": "SP-ARC-002",
        "name": "Security Architect",
        "category": "Securely Provision",
        "description": "Ensures that the stakeholder security requirements necessary to protect the organization's mission and business processes are adequately addressed in all aspects of enterprise architecture including reference models, segment and solution architectures, and the resulting systems.",
    },
    {
        "id": "SP-TRD-001",
        "name": "Research & Development Specialist",
        "category": "Securely Provision",
        "description": "Conducts software and systems engineering and software systems research to develop new capabilities, ensuring cybersecurity is fully integrated.",
    },
    {
        "id": "SP-SRP-001",
        "name": "Systems Requirements Planner",
        "category": "Securely Provision",
        "description": "Consults with customers to evaluate functional requirements and translates functional requirements into technical solutions.",
    },
    {
        "id": "SP-TST-001",
        "name": "System Testing and Evaluation Specialist",
        "category": "Securely Provision",
        "description": "Plans, prepares, and executes tests of systems to evaluate results against specifications and requirements as well as analyze/report test results.",
    },
    {
        "id": "SP-SYS-001",
        "name": "Information Systems Security Developer",
        "category": "Securely Provision",
        "description": "Designs, develops, tests, and evaluates information system security throughout the systems development life cycle.",
    },
    {
        "id": "SP-SYS-002",
        "name": "Systems Developer",
        "category": "Securely Provision",
        "description": "Designs, develops, tests, and evaluates information systems throughout the systems development life cycle.",
    },
    # Operate and Maintain (OM)
    {
        "id": "OM-DTA-001",
        "name": "Database Administrator",
        "category": "Operate and Maintain",
        "description": "Administers databases and/or data management systems that allow for the secure storage, query, protection, and utilization of data.",
    },
    {
        "id": "OM-DTA-002",
        "name": "Data Analyst",
        "category": "Operate and Maintain",
        "description": "Examines data from multiple disparate sources with the goal of providing security and privacy insight. Designs and implements custom algorithms, workflow processes, and layouts for complex, enterprise-scale data sets.",
    },
    {
        "id": "OM-KMG-001",
        "name": "Knowledge Manager",
        "category": "Operate and Maintain",
        "description": "Responsible for the management and administration of processes and tools that enable the organization to identify, document, and access intellectual capital and information content.",
    },
    {
        "id": "OM-NET-001",
        "name": "Network Operations Specialist",
        "category": "Operate and Maintain",
        "description": "Plans, implements, and operates network services/systems, to include hardware and virtual environments.",
    },
    {
        "id": "OM-ADM-001",
        "name": "System Administrator",
        "category": "Operate and Maintain",
        "description": "Responsible for setting up and maintaining a system or specific components of a system. Activities include installing, configuring, and updating hardware and software; establishing and managing user accounts; overseeing or conducting backup and recovery tasks.",
    },
    {
        "id": "OM-STS-001",
        "name": "Technical Support Specialist",
        "category": "Operate and Maintain",
        "description": "Provides technical support to customers who need assistance utilizing client-level hardware and software in accordance with established or approved organizational process components.",
    },
    # Oversee and Govern (OV)
    {
        "id": "OV-LGA-001",
        "name": "Cyber Legal Advisor",
        "category": "Oversee and Govern",
        "description": "Provides legal advice and recommendations on relevant topics related to cyber law.",
    },
    {
        "id": "OV-LGA-002",
        "name": "Privacy Officer/Privacy Compliance Manager",
        "category": "Oversee and Govern",
        "description": "Develops and oversees privacy compliance program and privacy program staff, supporting privacy compliance, governance/policy, and incident response needs of privacy and security executives and their teams.",
    },
    {
        "id": "OV-PMA-001",
        "name": "Cyber Workforce Developer and Manager",
        "category": "Oversee and Govern",
        "description": "Develops cyberspace workforce plans, strategies, and guidance to support cyberspace workforce manpower, personnel, training and education requirements and to address changes to cyberspace policy, doctrine, materiel, force structure, and education and training requirements.",
    },
    {
        "id": "OV-PMA-002",
        "name": "Cyber Instructor",
        "category": "Oversee and Govern",
        "description": "Develops and conducts training or education of personnel within cyber domain. Develops, plans, coordinates, delivers, and/or evaluates training courses, methods, and techniques as appropriate.",
    },
    {
        "id": "OV-PMA-003",
        "name": "Cyber Policy and Strategy Planner",
        "category": "Oversee and Govern",
        "description": "Develops and maintains cybersecurity plans, strategy, and policy to support and align with organizational cybersecurity initiatives and regulatory compliance.",
    },
    {
        "id": "OV-PMA-004",
        "name": "Executive Cyber Leadership",
        "category": "Oversee and Govern",
        "description": "Executes decision-making authorities and establishes vision and direction for an organization's cyber and cyber-related resources and/or operations.",
    },
    {
        "id": "OV-MGT-001",
        "name": "Information Systems Security Manager",
        "category": "Oversee and Govern",
        "description": "Responsible for the cybersecurity of a program, organization, system, or enclave.",
    },
    {
        "id": "OV-MGT-002",
        "name": "Communications Security (COMSEC) Manager",
        "category": "Oversee and Govern",
        "description": "Manages the Communications Security (COMSEC) resources of an organization or information system.",
    },
    {
        "id": "OV-SPP-001",
        "name": "Cyber Workforce Developer and Manager",
        "category": "Oversee and Govern",
        "description": "Develops cyberspace workforce plans, strategies, and guidance to support cyberspace workforce manpower, personnel, training and education requirements.",
    },
    {
        "id": "OV-EXL-001",
        "name": "Program Manager",
        "category": "Oversee and Govern",
        "description": "Leads, coordinates, communicates, integrates, and is accountable for the overall success of the program, ensuring alignment with critical agency and/or enterprise priorities.",
    },
    # Protect and Defend (PR)
    {
        "id": "PR-CDA-001",
        "name": "Cyber Defense Analyst",
        "category": "Protect and Defend",
        "description": "Uses defensive measures and information collected from a variety of sources to identify, analyze, and report events that occur or might occur within the network to protect information, information systems, and networks from threats.",
    },
    {
        "id": "PR-INF-001",
        "name": "Cyber Defense Infrastructure Support Specialist",
        "category": "Protect and Defend",
        "description": "Tests, implements, deploys, maintains, and administers the infrastructure hardware and software for cyber defense.",
    },
    {
        "id": "PR-CIR-001",
        "name": "Cyber Defense Incident Responder",
        "category": "Protect and Defend",
        "description": "Investigates, analyzes, and responds to cyber incidents within the network environment or enclave.",
    },
    {
        "id": "PR-VAM-001",
        "name": "Vulnerability Assessment Analyst",
        "category": "Protect and Defend",
        "description": "Performs assessments of systems and networks within the network environment or enclave and identifies where those systems/networks deviate from acceptable configurations, enclave policy, or local policy.",
    },
    # Analyze (AN)
    {
        "id": "AN-TWA-001",
        "name": "Threat/Warning Analyst",
        "category": "Analyze",
        "description": "Develops cyber indicators to maintain awareness of the status of the highly dynamic operating environment. Collects, processes, analyzes, and disseminates cyber threat/warning assessments.",
    },
    {
        "id": "AN-EXP-001",
        "name": "Exploitation Analyst",
        "category": "Analyze",
        "description": "Collaborates to identify access and collection gaps that can be satisfied through cyber collection and/or preparation activities. Leverages all authorized resources and analytic techniques to penetrate targeted networks.",
    },
    {
        "id": "AN-ASA-001",
        "name": "All-Source Analyst",
        "category": "Analyze",
        "description": "Analyzes data/information from one or multiple sources to conduct preparation of the environment, respond to requests for information, and submit intelligence collection and production requirements in support of planning and operations.",
    },
    {
        "id": "AN-ASA-002",
        "name": "Mission Assessment Specialist",
        "category": "Analyze",
        "description": "Develops assessment plans and measures of performance/effectiveness. Conducts strategic and operational effectiveness assessments as required for cyber events. Determines whether systems performed as expected and provides input to the determination of operational effectiveness.",
    },
    {
        "id": "AN-TGT-001",
        "name": "Target Developer",
        "category": "Analyze",
        "description": "Performs target system analysis, builds and/or maintains electronic target folders to include inputs from environment preparation, and/or internal or external intelligence sources. Coordinates with partner target activities and intelligence organizations.",
    },
    {
        "id": "AN-TGT-002",
        "name": "Target Network Analyst",
        "category": "Analyze",
        "description": "Conducts advanced analysis of collection and open-source data to ensure target continuity; profiling targets and their activities; and developing techniques to gain more target information.",
    },
    {
        "id": "AN-LNG-001",
        "name": "Multi-Disciplined Language Analyst",
        "category": "Analyze",
        "description": "Applies language and culture expertise with target/threat and technical knowledge to process, analyze, and/or disseminate intelligence information derived from language, voice, and/or graphic material.",
    },
    # Collect and Operate (CO)
    {
        "id": "CO-CLO-001",
        "name": "All Source-Collection Manager",
        "category": "Collect and Operate",
        "description": "Identifies collection authorities and environment; incorporates priority information requirements into collection management; develops concepts to meet leadership's intent.",
    },
    {
        "id": "CO-CLO-002",
        "name": "All Source-Collection Requirements Manager",
        "category": "Collect and Operate",
        "description": "Evaluates collection operations and develops effects-based collection requirements strategies using available sources and methods to improve collection. Develops, processes, validates, and coordinates submission of collection requirements.",
    },
    {
        "id": "CO-OPL-001",
        "name": "Cyber Intel Planner",
        "category": "Collect and Operate",
        "description": "Develops detailed intelligence plans to satisfy cyber operations requirements. Collaborates with cyber operations planners to identify, validate, and levy requirements for collection and analysis.",
    },
    {
        "id": "CO-OPL-002",
        "name": "Cyber Ops Planner",
        "category": "Collect and Operate",
        "description": "Develops detailed plans for the conduct or support of the applicable range of cyber operations through collaboration with other planners, operators, and/or analysts.",
    },
    {
        "id": "CO-OPL-003",
        "name": "Partner Integration Planner",
        "category": "Collect and Operate",
        "description": "Works to advance cooperation across organizational or national borders between cyber operations partners. Aids in planning of cyber operations partner integration and coordination.",
    },
    {
        "id": "CO-OPS-001",
        "name": "Cyber Operator",
        "category": "Collect and Operate",
        "description": "Conducts collection, processing, and/or geolocation of systems to exploit, locate, and/or track targets of interest. Performs network navigation, tactical forensic analysis, and, when directed, executes on-net operations.",
    },
    # Investigate (IN)
    {
        "id": "IN-FOR-001",
        "name": "Cyber Crime Investigator",
        "category": "Investigate",
        "description": "Identifies, collects, examines, and preserves evidence using controlled and documented analytical and investigative techniques.",
    },
    {
        "id": "IN-FOR-002",
        "name": "Digital Forensics Analyst",
        "category": "Investigate",
        "description": "Analyzes digital evidence and investigates computer security incidents to derive useful information in support of system/network vulnerability mitigation.",
    },
    {
        "id": "IN-INV-001",
        "name": "Cyber Defense Forensics Analyst",
        "category": "Investigate",
        "description": "Analyzes digital evidence and investigates computer security incidents to derive useful information in support of system/network vulnerability mitigation.",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrape_nice(db: sqlite3.Connection) -> int:
    """Populate the ``nice_roles`` table with NICE Framework data.

    Uses hardcoded reference data from NICE Framework v2.1 (SP 800-181r1).
    Returns the number of rows inserted.
    """
    rows: list[dict[str, Any]] = []

    # Insert categories as top-level entries
    for cat in _CATEGORIES:
        rows.append({
            "id": cat["id"],
            "name": cat["name"],
            "category": cat["category"],
            "description": cat["description"],
            "knowledge": None,
            "skills": None,
            "tasks": None,
        })

    # Insert work roles
    for role in _WORK_ROLES:
        rows.append({
            "id": role["id"],
            "name": role["name"],
            "category": role["category"],
            "description": role["description"],
            "knowledge": role.get("knowledge"),
            "skills": role.get("skills"),
            "tasks": role.get("tasks"),
        })

    db.execute("DELETE FROM nice_roles")
    db.executemany(
        """
        INSERT INTO nice_roles (id, name, category, description, knowledge, skills, tasks)
        VALUES (:id, :name, :category, :description, :knowledge, :skills, :tasks)
        """,
        rows,
    )
    db.commit()
    log.info("Inserted %d NICE Framework entries", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = scrape_nice(conn)
    print(f"Inserted {n} NICE entries")

    cur = conn.execute(
        "SELECT DISTINCT category, COUNT(*) FROM nice_roles GROUP BY category"
    )
    for row in cur:
        print(f"  {row[0]}: {row[1]} roles")

    cur = conn.execute("SELECT id, name FROM nice_roles LIMIT 10")
    for row in cur:
        print(f"  {row}")
    conn.close()
