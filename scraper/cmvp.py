"""Scraper for CMVP (Cryptographic Module Validation Program) data.

The CMVP validated modules list at csrc.nist.gov is JS-rendered and not
directly scrapeable with simple HTTP requests.  This module provides a curated
dataset of well-known FIPS 140-2/3 validated cryptographic modules as a
starting point, with a TODO for future API/scraping integration when NIST
publishes a machine-readable endpoint.
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
CREATE TABLE IF NOT EXISTS cmvp (
    cert_number     TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    module_name     TEXT NOT NULL,
    module_type     TEXT,
    fips_level      TEXT,
    status          TEXT,
    validation_date TEXT,
    expiration_date TEXT,
    algorithms      TEXT,          -- comma-separated
    description     TEXT
);
CREATE INDEX IF NOT EXISTS idx_cmvp_vendor ON cmvp(vendor);
CREATE INDEX IF NOT EXISTS idx_cmvp_status ON cmvp(status);
CREATE INDEX IF NOT EXISTS idx_cmvp_level ON cmvp(fips_level);
"""

# ---------------------------------------------------------------------------
# Curated CMVP validated modules
#
# This is a starter dataset of widely-deployed FIPS 140-2/3 validated
# cryptographic modules.  A proper scraper or API integration should replace
# this once NIST publishes a stable machine-readable CMVP endpoint.
#
# TODO: Replace with live scraping or API when available.
# ---------------------------------------------------------------------------

_CURATED_MODULES: list[dict[str, Any]] = [
    {
        "cert_number": "4282",
        "vendor": "Google LLC",
        "module_name": "BoringCrypto",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2023-10-25",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "BoringCrypto is the FIPS 140-2 validated cryptographic module used in BoringSSL, Google's fork of OpenSSL.",
    },
    {
        "cert_number": "4407",
        "vendor": "Amazon Web Services",
        "module_name": "AWS-LC Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-01-19",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH, EdDSA",
        "description": "AWS Libcrypto (AWS-LC) is a FIPS-validated cryptographic library used across AWS services.",
    },
    {
        "cert_number": "3196",
        "vendor": "OpenSSL Software Foundation",
        "module_name": "OpenSSL FIPS Provider",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2020-07-20",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "The OpenSSL FIPS Provider is the FIPS 140-2 validated cryptographic module for OpenSSL 3.x.",
    },
    {
        "cert_number": "4536",
        "vendor": "Microsoft Corporation",
        "module_name": "Windows CNG Cryptographic Primitives Library",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-05-10",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH, EdDSA",
        "description": "Cryptography Next Generation (CNG) Primitives Library for Windows operating systems.",
    },
    {
        "cert_number": "4535",
        "vendor": "Microsoft Corporation",
        "module_name": "Windows Kernel Mode Cryptographic Primitives Library",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-05-10",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Kernel mode cryptographic primitives library for Windows operating systems.",
    },
    {
        "cert_number": "4177",
        "vendor": "Apple Inc.",
        "module_name": "Apple corecrypto Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2023-06-27",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH, EdDSA",
        "description": "Apple's corecrypto module provides cryptographic services for macOS, iOS, iPadOS, tvOS, and watchOS.",
    },
    {
        "cert_number": "3980",
        "vendor": "Red Hat, Inc.",
        "module_name": "Red Hat Enterprise Linux OpenSSL Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-12-14",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "OpenSSL cryptographic module as shipped in Red Hat Enterprise Linux.",
    },
    {
        "cert_number": "3816",
        "vendor": "Canonical Ltd.",
        "module_name": "Ubuntu OpenSSL Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-06-15",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "OpenSSL FIPS module as distributed with Ubuntu Linux.",
    },
    {
        "cert_number": "3632",
        "vendor": "Oracle Corporation",
        "module_name": "Oracle Linux OpenSSL Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-09-22",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "OpenSSL FIPS module as distributed with Oracle Linux.",
    },
    {
        "cert_number": "3615",
        "vendor": "Cisco Systems, Inc.",
        "module_name": "Cisco Common Crypto Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-08-25",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Common cryptographic module used across Cisco products and platforms.",
    },
    {
        "cert_number": "3699",
        "vendor": "Samsung Electronics Co., Ltd.",
        "module_name": "Samsung Kernel Crypto Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-12-16",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG",
        "description": "Kernel-mode cryptographic module for Samsung devices running Android.",
    },
    {
        "cert_number": "4398",
        "vendor": "Fortanix, Inc.",
        "module_name": "Fortanix FIPS Crypto Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-01-08",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH, EdDSA",
        "description": "Rust-based FIPS 140-3 validated cryptographic module.",
    },
    {
        "cert_number": "3608",
        "vendor": "wolfSSL Inc.",
        "module_name": "wolfCrypt FIPS Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-08-16",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "wolfCrypt is a lightweight, portable FIPS 140-2 validated cryptographic library.",
    },
    {
        "cert_number": "4515",
        "vendor": "Google LLC",
        "module_name": "BoringCrypto (FIPS 140-3)",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-04-15",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH, EdDSA",
        "description": "BoringCrypto FIPS 140-3 validated module for BoringSSL.",
    },
    {
        "cert_number": "3928",
        "vendor": "VMware, Inc.",
        "module_name": "VMware OpenSSL FIPS Object Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-10-17",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "OpenSSL-based FIPS module for VMware products.",
    },
    {
        "cert_number": "3765",
        "vendor": "Thales Group",
        "module_name": "Luna Network HSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2022-03-15",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH, EdDSA",
        "description": "Luna Network HSM is a high-assurance FIPS 140-2 Level 3 validated hardware security module.",
    },
    {
        "cert_number": "4162",
        "vendor": "Entrust Corporation",
        "module_name": "nShield Connect XC HSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2023-06-12",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "nShield Connect XC is a FIPS 140-2 Level 3 validated network-attached HSM from Entrust (formerly nCipher).",
    },
    {
        "cert_number": "4233",
        "vendor": "AWS",
        "module_name": "AWS CloudHSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2023-09-05",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "AWS CloudHSM provides FIPS 140-2 Level 3 validated hardware security modules in the AWS cloud.",
    },
    {
        "cert_number": "3718",
        "vendor": "Marvell Semiconductor",
        "module_name": "Marvell LiquidSecurity HSM Adapter",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2022-01-10",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "LiquidSecurity HSM Adapter is a PCIe-based FIPS 140-2 Level 3 validated HSM.",
    },
    {
        "cert_number": "4461",
        "vendor": "Utimaco IS GmbH",
        "module_name": "Utimaco SecurityServer Se Gen2 HSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2024-02-28",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH, EdDSA",
        "description": "Utimaco SecurityServer Se Gen2 is a FIPS 140-2 Level 3 validated general-purpose HSM.",
    },
    {
        "cert_number": "3223",
        "vendor": "Intel Corporation",
        "module_name": "Intel Integrated Performance Primitives Cryptographic Library",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2020-09-04",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG",
        "description": "IPP Crypto is a FIPS 140-2 validated cryptographic library optimized for Intel processors.",
    },
    {
        "cert_number": "3583",
        "vendor": "GnuTLS project",
        "module_name": "GnuTLS Cryptographic Module (Libgcrypt)",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-07-12",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Libgcrypt is the cryptographic library used by GnuTLS and GnuPG.",
    },
    {
        "cert_number": "3511",
        "vendor": "Bouncy Castle",
        "module_name": "BC-FJA (Bouncy Castle FIPS Java API)",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-03-30",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Bouncy Castle FIPS Java API provides FIPS 140-2 validated cryptography for Java applications.",
    },
    {
        "cert_number": "3514",
        "vendor": "Bouncy Castle",
        "module_name": "BC-FNA (Bouncy Castle FIPS .NET API)",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-04-01",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Bouncy Castle FIPS .NET API provides FIPS 140-2 validated cryptography for .NET applications.",
    },
    {
        "cert_number": "4497",
        "vendor": "HashiCorp",
        "module_name": "HashiCorp Vault Enterprise FIPS Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-03-22",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "FIPS 140-2 validated cryptographic module used in HashiCorp Vault Enterprise.",
    },
    {
        "cert_number": "3895",
        "vendor": "IBM Corporation",
        "module_name": "IBM Crypto for C (ICC)",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-09-08",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, SHA-3, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "IBM Crypto for C is a FIPS 140-2 validated cryptographic library used across IBM products.",
    },
    {
        "cert_number": "3550",
        "vendor": "Mozilla Foundation",
        "module_name": "Network Security Services (NSS) Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-05-19",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "NSS is the cryptographic library used by Firefox, Thunderbird, and other Mozilla products.",
    },
    {
        "cert_number": "3725",
        "vendor": "Yubico AB",
        "module_name": "YubiKey FIPS (5 Series)",
        "module_type": "Hardware",
        "fips_level": "2",
        "status": "Active",
        "validation_date": "2022-01-25",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG",
        "description": "YubiKey 5 FIPS series provides FIPS 140-2 Level 2 validated hardware authentication.",
    },
    {
        "cert_number": "3902",
        "vendor": "Palo Alto Networks",
        "module_name": "Palo Alto Networks Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-09-20",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module used in Palo Alto Networks firewalls and security appliances.",
    },
    {
        "cert_number": "3562",
        "vendor": "Juniper Networks",
        "module_name": "Juniper Networks Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-06-03",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module used in Juniper Networks routers and security devices.",
    },
    {
        "cert_number": "3786",
        "vendor": "Fortinet, Inc.",
        "module_name": "FortiOS Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-04-12",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module used in FortiGate firewalls and FortiOS-based products.",
    },
    {
        "cert_number": "3841",
        "vendor": "Check Point Software Technologies",
        "module_name": "Check Point Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-07-21",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module for Check Point security gateways and management.",
    },
    {
        "cert_number": "4070",
        "vendor": "CrowdStrike, Inc.",
        "module_name": "CrowdStrike Falcon Sensor Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2023-03-15",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF",
        "description": "Cryptographic module used in the CrowdStrike Falcon endpoint protection sensor.",
    },
    {
        "cert_number": "3651",
        "vendor": "Microchip Technology Inc.",
        "module_name": "ATECC608B Secure Element",
        "module_type": "Hardware",
        "fips_level": "2",
        "status": "Active",
        "validation_date": "2021-10-14",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, ECDSA, HMAC, ECDH",
        "description": "ATECC608B is a FIPS 140-2 Level 2 validated secure element for IoT and embedded systems.",
    },
    {
        "cert_number": "3859",
        "vendor": "NXP Semiconductors",
        "module_name": "NXP EdgeLock SE050 Secure Element",
        "module_type": "Hardware",
        "fips_level": "2",
        "status": "Active",
        "validation_date": "2022-08-04",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, RSA, ECDSA, HMAC, ECDH",
        "description": "EdgeLock SE050 is a FIPS 140-2 Level 2 validated secure element for IoT devices.",
    },
    {
        "cert_number": "3394",
        "vendor": "Oracle Corporation",
        "module_name": "Oracle Java SE JCE Provider",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2020-12-22",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Java Cryptography Extension (JCE) provider for Oracle Java SE.",
    },
    {
        "cert_number": "3690",
        "vendor": "Microsoft Corporation",
        "module_name": "Microsoft .NET Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-11-30",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Managed cryptographic module for .NET applications on Windows.",
    },
    {
        "cert_number": "4350",
        "vendor": "Amazon Web Services",
        "module_name": "AWS Key Management Service HSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2023-12-12",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Hardware security module backing AWS Key Management Service (KMS).",
    },
    {
        "cert_number": "4225",
        "vendor": "Google LLC",
        "module_name": "Google Cloud HSM (Marvell LiquidSecurity)",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2023-08-28",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "HSMs powering Google Cloud KMS, validated at FIPS 140-2 Level 3.",
    },
    {
        "cert_number": "4105",
        "vendor": "Microsoft Corporation",
        "module_name": "Azure Managed HSM",
        "module_type": "Hardware",
        "fips_level": "3",
        "status": "Active",
        "validation_date": "2023-04-19",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Hardware security modules backing Azure Key Vault Managed HSM.",
    },
    {
        "cert_number": "3740",
        "vendor": "Qualcomm Technologies, Inc.",
        "module_name": "Qualcomm Crypto Engine",
        "module_type": "Hardware",
        "fips_level": "2",
        "status": "Active",
        "validation_date": "2022-02-08",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG",
        "description": "Hardware cryptographic engine in Qualcomm Snapdragon SoCs.",
    },
    {
        "cert_number": "4310",
        "vendor": "ARM Limited",
        "module_name": "Arm CryptoCell",
        "module_type": "Hardware",
        "fips_level": "2",
        "status": "Active",
        "validation_date": "2023-11-15",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, RSA, ECDSA, HMAC, DRBG, ECDH",
        "description": "CryptoCell is a hardware cryptographic accelerator IP for Arm Cortex processors.",
    },
    {
        "cert_number": "3975",
        "vendor": "SonicWall Inc.",
        "module_name": "SonicOS Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-11-28",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module for SonicWall firewalls running SonicOS.",
    },
    {
        "cert_number": "3410",
        "vendor": "Citrix Systems, Inc.",
        "module_name": "Citrix ADC Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-01-14",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module for Citrix Application Delivery Controller (ADC/NetScaler).",
    },
    {
        "cert_number": "3870",
        "vendor": "F5 Networks, Inc.",
        "module_name": "F5 BIG-IP Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-08-22",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module for F5 BIG-IP application delivery controllers.",
    },
    {
        "cert_number": "3445",
        "vendor": "SUSE LLC",
        "module_name": "SUSE Linux Enterprise Server OpenSSL Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-02-09",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, DSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "OpenSSL FIPS module as shipped in SUSE Linux Enterprise Server.",
    },
    {
        "cert_number": "3950",
        "vendor": "Zscaler, Inc.",
        "module_name": "Zscaler Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2022-11-01",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "Cryptographic module used in Zscaler Zero Trust Exchange platform.",
    },
    {
        "cert_number": "4560",
        "vendor": "Cloudflare, Inc.",
        "module_name": "Cloudflare BoringCrypto Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2024-06-03",
        "expiration_date": "",
        "algorithms": "AES, SHA-2, SHA-3, RSA, ECDSA, HMAC, DRBG, KDF, ECDH",
        "description": "BoringCrypto-based FIPS module used in Cloudflare edge services.",
    },
    {
        "cert_number": "3490",
        "vendor": "Aruba Networks (HPE)",
        "module_name": "ArubaOS Cryptographic Module",
        "module_type": "Software",
        "fips_level": "1",
        "status": "Active",
        "validation_date": "2021-03-10",
        "expiration_date": "",
        "algorithms": "AES, SHA-1, SHA-2, RSA, ECDSA, HMAC, DRBG, KDF, DH, ECDH",
        "description": "Cryptographic module for Aruba Networks wireless controllers and access points.",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_CMVP_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search/all"
_TIMEOUT = 60


def _scrape_cmvp_html() -> list[dict[str, Any]] | None:
    """Scrape the CMVP validated modules HTML table."""
    import httpx
    from bs4 import BeautifulSoup

    try:
        client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        resp = client.get(_CMVP_URL)
        resp.raise_for_status()
        client.close()
    except Exception:
        log.warning("CMVP HTML download failed", exc_info=True)
        return None

    soup = BeautifulSoup(resp.text, "lxml")
    table = soup.find("table")
    if not table:
        log.warning("No table found on CMVP page")
        return None

    rows_out: list[dict[str, Any]] = []
    for row in table.find_all("tr")[1:]:  # skip header
        cells = row.find_all("td")
        if len(cells) < 5:
            continue

        cert_number = cells[0].get_text(strip=True)
        vendor = cells[1].get_text(strip=True)
        module_name = cells[2].get_text(strip=True)
        module_type = cells[3].get_text(strip=True)
        validation_date = cells[4].get_text(strip=True)

        rows_out.append({
            "cert_number": cert_number,
            "vendor": vendor,
            "module_name": module_name,
            "module_type": module_type.replace("-", " ").title() if module_type else None,
            "fips_level": None,  # not in the table, would need detail page
            "status": "Active",
            "validation_date": validation_date,
            "expiration_date": None,
            "algorithms": None,  # not in the table
            "description": None,
        })

    return rows_out if rows_out else None


def scrape_cmvp(db: sqlite3.Connection) -> int:
    """Populate the ``cmvp`` table with CMVP validated module data.

    Tries to scrape the full CMVP list from csrc.nist.gov. Falls back to
    curated reference data if scraping fails.
    Returns the number of rows inserted.
    """
    rows = _scrape_cmvp_html()
    if rows:
        log.info("Scraped %d CMVP modules from NIST", len(rows))
    else:
        rows = _CURATED_MODULES
        log.info("Using curated CMVP data: %d modules", len(rows))

    db.execute("DELETE FROM cmvp")
    db.executemany(
        """
        INSERT INTO cmvp (
            cert_number, vendor, module_name, module_type, fips_level,
            status, validation_date, expiration_date, algorithms, description
        ) VALUES (
            :cert_number, :vendor, :module_name, :module_type, :fips_level,
            :status, :validation_date, :expiration_date, :algorithms, :description
        )
        """,
        rows,
    )
    db.commit()
    log.info("Inserted %d CMVP validated modules", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = scrape_cmvp(conn)
    print(f"Inserted {n} CMVP modules")

    cur = conn.execute(
        "SELECT module_type, COUNT(*) FROM cmvp GROUP BY module_type"
    )
    for row in cur:
        print(f"  {row[0]}: {row[1]}")

    cur = conn.execute(
        "SELECT cert_number, vendor, module_name FROM cmvp LIMIT 10"
    )
    for row in cur:
        print(f"  #{row[0]} {row[1]}: {row[2]}")
    conn.close()
