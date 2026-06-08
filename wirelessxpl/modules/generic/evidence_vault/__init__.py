"""Evidence Vault - tamper-evident audit ledger for WiFi security assessments.

Adapted from gandalf-the-white (salli94) for WirelessXPL-Forge.
Provides forensically defensible chain-of-custody compatible with ISO/IEC 27037.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from .evidence_vault import EvidenceVault, WifiEvidenceVault

__all__ = ["EvidenceVault", "WifiEvidenceVault"]
