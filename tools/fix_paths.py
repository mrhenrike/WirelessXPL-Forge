#!/usr/bin/env python3
"""Corrige prefixos de grupo nos paths de modulos do wxf_campaign.py."""
from pathlib import Path

target = Path(__file__).parent / "wxf_campaign.py"
c = target.read_text(encoding="utf-8")
groups = ["wifi_lab", "bluetooth", "pcap", "external", "cellular", "sim"]
for g in groups:
    c = c.replace(f'"{g}/', f'"generic/{g}/')
target.write_text(c, encoding="utf-8")
print("Paths corrigidos")
