"""FastMCP server definition and entry point for nist-mcp."""

from __future__ import annotations

from fastmcp import FastMCP

from nist_mcp import __version__
from nist_mcp.config import get_config
from nist_mcp.index import IndexManager
from nist_mcp.tools.admin import _format_size

mcp = FastMCP(
    name="nist-mcp",
    instructions=(
        "NIST MCP server providing access to NIST publications (SP 800, SP 1800, FIPS, IR, CSWP, AI), "
        "SP 800-53 security controls, NIST CSF 2.0 framework, NVD vulnerability data (CVEs, CPEs), "
        "CMVP validated cryptographic modules, NCP security checklists, NIST glossary, "
        "and NICE Framework work roles. "
        "Start with search_nist for broad queries, or use domain-specific tools for targeted lookups. "
        "Use search_publications for documents, search_controls for SP 800-53, get_csf_data for frameworks, "
        "search_cves for vulnerabilities, lookup_glossary for terminology."
    ),
)


# ---------------------------------------------------------------------------
# Static MCP Resources
# ---------------------------------------------------------------------------

_STATIC_ANNOTATIONS = {"readOnlyHint": True, "idempotentHint": True}

_CONTROL_FAMILIES = """\
# SP 800-53 Control Families

| ID | Family |
|----|--------|
| AC | Access Control — Policies and mechanisms for controlling system access |
| AT | Awareness and Training — Security training and awareness programs |
| AU | Audit and Accountability — Audit logging, review, and retention |
| CA | Assessment, Authorization, and Monitoring — Security assessments and authorizations |
| CM | Configuration Management — Baseline configurations and change control |
| CP | Contingency Planning — Business continuity and disaster recovery |
| IA | Identification and Authentication — Identity verification mechanisms |
| IR | Incident Response — Incident detection, handling, and reporting |
| MA | Maintenance — System maintenance policies and procedures |
| MP | Media Protection — Media access, marking, storage, and sanitization |
| PE | Physical and Environmental Protection — Physical access and environmental controls |
| PL | Planning — Security planning and system security plans |
| PM | Program Management — Organization-wide information security program |
| PS | Personnel Security — Personnel screening and access agreements |
| PT | PII Processing and Transparency — Personally identifiable information handling |
| RA | Risk Assessment — Risk identification, analysis, and response |
| SA | System and Services Acquisition — Secure development and supply chain |
| SC | System and Communications Protection — Cryptography and communications safeguards |
| SI | System and Information Integrity — Flaw remediation, monitoring, and malware protection |
| SR | Supply Chain Risk Management — Supply chain controls and provenance |
"""


@mcp.resource("nist://controls/families", annotations=_STATIC_ANNOTATIONS)
def controls_families() -> str:
    """All 20 SP 800-53 Rev 5 control families with one-line descriptions."""
    return _CONTROL_FAMILIES


_BASELINES = """\
# SP 800-53 Security Control Baselines

SP 800-53B defines four baselines that assign controls to systems based on impact level.

## LOW Baseline
For systems where the loss of confidentiality, integrity, or availability would have \
a **limited** adverse effect. Includes approximately 155 controls focusing on \
fundamental security hygiene.

## MODERATE Baseline
For systems where loss would have a **serious** adverse effect. Includes approximately \
325 controls adding stronger access control, auditing, and incident response.

## HIGH Baseline
For systems where loss would have a **severe or catastrophic** adverse effect. Includes \
approximately 380 controls with the most rigorous protections, including redundancy and \
advanced monitoring.

## PRIVACY Baseline
Controls specifically applicable to systems processing personally identifiable \
information (PII), drawn from the PT (PII Processing and Transparency) family and \
privacy-relevant controls across other families. Includes approximately 110 controls.
"""


@mcp.resource("nist://controls/baselines", annotations=_STATIC_ANNOTATIONS)
def controls_baselines() -> str:
    """LOW, MODERATE, HIGH, and PRIVACY baselines with control counts."""
    return _BASELINES


_CSF_OVERVIEW = """\
# NIST Cybersecurity Framework (CSF) 2.0

CSF 2.0 organizes cybersecurity outcomes into 6 core Functions:

## GV — Govern
Establish and monitor the organization's cybersecurity risk management strategy, \
expectations, and policy. Provides context for all other Functions.

## ID — Identify
Understand the organization's current cybersecurity risks by identifying assets, \
vulnerabilities, threats, and risk to critical services.

## PR — Protect
Use safeguards to manage the organization's cybersecurity risks. Covers identity \
management, access control, awareness training, data security, and platform security.

## DE — Detect
Find and analyze possible cybersecurity attacks and compromises through continuous \
monitoring and anomaly analysis.

## RS — Respond
Take action regarding a detected cybersecurity incident. Includes incident management, \
analysis, reporting, mitigation, and communication.

## RC — Recover
Restore assets and operations affected by a cybersecurity incident. Covers recovery \
planning, execution, and communication.

---

Each Function contains Categories (e.g., ID.AM — Asset Management) and Subcategories \
(e.g., ID.AM-01) that provide specific outcomes. CSF 2.0 also introduces Community \
Profiles and the new Govern function compared to v1.1.
"""


@mcp.resource("nist://csf/overview", annotations=_STATIC_ANNOTATIONS)
def csf_overview() -> str:
    """CSF 2.0 structure: 6 Functions with descriptions."""
    return _CSF_OVERVIEW


_COMMON_GLOSSARY = """\
# Common NIST Cybersecurity Terms

**Access Control** — The process of granting or denying specific requests to obtain \
and use information and related information processing services.

**Assessment** — The testing or evaluation of security controls to determine the extent \
to which the controls are implemented correctly, operating as intended, and producing \
the desired outcome.

**Audit** — An independent review and examination of records and activities to assess \
the adequacy of system controls and ensure compliance with established policies.

**Authentication** — Verifying the identity of a user, process, or device, often as a \
prerequisite to allowing access to a system's resources.

**Authorization** — The right or a permission granted to a system entity to access a \
system resource.

**Availability** — Ensuring timely and reliable access to and use of information.

**Baseline** — A minimum set of security controls selected to protect a system based on \
its impact level (LOW, MODERATE, or HIGH).

**Confidentiality** — Preserving authorized restrictions on information access and \
disclosure, including means for protecting personal privacy and proprietary information.

**Continuous Monitoring** — Maintaining ongoing awareness of information security, \
vulnerabilities, and threats to support organizational risk management decisions.

**Control** — A safeguard or countermeasure prescribed for an information system or \
organization to protect the confidentiality, integrity, and availability of the system \
and its information.

**Control Enhancement** — A statement that augments a security control to build in \
additional but related capability or to increase the strength of the control.

**Cryptographic Module** — The set of hardware, software, and/or firmware that \
implements approved security functions, including cryptographic algorithms and key \
generation.

**CVE (Common Vulnerabilities and Exposures)** — A standardized identifier for a known \
cybersecurity vulnerability, maintained by MITRE and used by NVD.

**Encryption** — The process of converting information into a form unintelligible to \
anyone except holders of a specific cryptographic key.

**FIPS (Federal Information Processing Standards)** — Standards issued by NIST for use \
by federal agencies, covering topics such as encryption (FIPS 140-3) and hashing (FIPS 180-4).

**FISMA (Federal Information Security Modernization Act)** — US law requiring federal \
agencies to develop, document, and implement information security programs.

**Impact Level** — The magnitude of harm (LOW, MODERATE, or HIGH) expected from the \
loss of confidentiality, integrity, or availability of information.

**Incident** — An occurrence that actually or potentially jeopardizes the \
confidentiality, integrity, or availability of an information system.

**Integrity** — Guarding against improper information modification or destruction, \
including ensuring information non-repudiation and authenticity.

**NICE Framework** — The National Initiative for Cybersecurity Education framework \
that categorizes cybersecurity work into roles, competencies, and tasks.

**NVD (National Vulnerability Database)** — The US government repository of \
vulnerability management data, maintained by NIST, built upon CVE identifiers.

**Overlay** — A specification of security controls, control enhancements, supplemental \
guidance, and other supporting information tailored to a specific technology or sector.

**Risk** — A measure of the extent to which an entity is threatened by a potential \
circumstance or event, expressed as a function of likelihood and impact.

**Risk Assessment** — The process of identifying risks to organizational operations, \
assets, individuals, and other organizations.

**Risk Management Framework (RMF)** — The NIST process for managing information \
security risk: categorize, select, implement, assess, authorize, and monitor.

**Security Control** — See *Control*.

**Special Publication (SP)** — A series of NIST publications providing guidelines and \
recommendations on information security topics (e.g., SP 800-53, SP 800-171).

**Supply Chain Risk** — Risks arising from the loss of confidentiality, integrity, or \
availability of information or systems that result from use of products or services \
produced by third parties.

**Threat** — Any circumstance or event with the potential to adversely impact \
organizational operations, assets, or individuals through an information system.

**Vulnerability** — A weakness in a system, its procedures, internal controls, or \
implementation that could be exploited by a threat source.

**Zero Trust Architecture** — A security model that requires strict identity \
verification for every person and device trying to access resources, regardless of \
network location.
"""


@mcp.resource("nist://glossary/common", annotations=_STATIC_ANNOTATIONS)
def glossary_common() -> str:
    """Top ~30 most commonly referenced NIST cybersecurity terms and definitions."""
    return _COMMON_GLOSSARY


# ---------------------------------------------------------------------------
# Dynamic MCP Resource (registered in main() to capture index_mgr)
# ---------------------------------------------------------------------------


def _register_about_resource(index_mgr: IndexManager) -> None:
    """Register the nist://about resource that needs runtime state."""

    @mcp.resource("nist://about", annotations={"readOnlyHint": True})
    def about() -> str:
        """Server version, data freshness, and available tools guide."""
        info = index_mgr.status()
        db_available = "Yes" if info["exists"] else "No"
        version_tag = info.get("current_tag", "unknown")
        last_check = info.get("last_check", "never")
        db_size = _format_size(info.get("db_size_bytes"))

        return (
            f"# NIST MCP Server\n\n"
            f"- **Server version:** {__version__}\n"
            f"- **Database version:** {version_tag}\n"
            f"- **Database available:** {db_available}\n"
            f"- **Last update check:** {last_check}\n"
            f"- **Database size:** {db_size}\n\n"
            f"## Available Tool Groups\n\n"
            f"| Group | Description |\n"
            f"|-------|-------------|\n"
            f"| **Admin** | `update_database`, `database_status` — manage the local index |\n"
            f"| **Publications** | Search and retrieve NIST SP 800, SP 1800, FIPS, IR, CSWP, AI docs |\n"
            f"| **Controls** | Query SP 800-53 Rev 5 controls, enhancements, and baselines |\n"
            f"| **Frameworks** | CSF 2.0, RMF, and NICE Framework data |\n"
            f"| **NVD** | Search CVEs, CPEs, and KEV catalog entries |\n"
            f"| **Compliance** | CMVP validated modules and NCP security checklists |\n"
            f"| **Reference** | NIST glossary lookups and cross-reference searches |\n\n"
            f"## Quick Start\n\n"
            f"- **Broad search:** Use `search_nist` for general queries\n"
            f"- **Documents:** Use `search_publications` to find specific NIST publications\n"
            f"- **Controls:** Use `search_controls` to look up SP 800-53 controls\n"
            f"- **Frameworks:** Use `get_csf_data` for CSF 2.0 categories and subcategories\n"
            f"- **Vulnerabilities:** Use `search_cves` for CVE lookups\n"
            f"- **Terminology:** Use `lookup_glossary` for NIST definitions\n"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Configure and run the NIST MCP server."""
    config = get_config()
    index_mgr = IndexManager(config)

    # Register tool groups (pass dependencies they need)
    from nist_mcp.tools.admin import register_admin_tools
    from nist_mcp.tools.controls import register_control_tools
    from nist_mcp.tools.publications import register_publication_tools
    from nist_mcp.tools.frameworks import register_framework_tools
    from nist_mcp.tools.reference import register_reference_tools
    from nist_mcp.tools.compliance import register_compliance_tools
    from nist_mcp.nvd import NVDClient
    from nist_mcp.kev import KEVClient
    from nist_mcp.tools.nvd import register_nvd_tools

    register_admin_tools(mcp, index_mgr)
    register_publication_tools(mcp, index_mgr, config)
    register_control_tools(mcp, index_mgr)
    register_framework_tools(mcp, index_mgr)
    register_reference_tools(mcp, index_mgr)
    register_compliance_tools(mcp, index_mgr)

    nvd_client = NVDClient(api_key=config.nvd_api_key)
    kev_client = KEVClient(cache_dir=config.data_dir)
    register_nvd_tools(mcp, nvd_client, kev_client)

    # Register the dynamic about resource (needs index_mgr)
    _register_about_resource(index_mgr)

    mcp.run()
