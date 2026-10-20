"""CVE Lookup by Banner / Vendor / Product / Version.

Queries the embedded CVE database to list known vulnerabilities for a
target device identified by banner grabbing, vendor name, product model
or firmware version. Classifies each CVE by access vector (REMOTE vs
LOCAL vs PHYSICAL) and indicates which ones have WirelessXPL-Forge exploit
modules available for immediate use.

Author: André Henrique (@mrhenrike) | União Geek - https://github.com/Uniao-Geek
"""

from wirelessxpl.core.cve.cve_db import CVEDatabase
from wirelessxpl.core.exploit import *


class Exploit(Exploit):
    __info__ = {
        "name": "CVE Lookup by Banner / Vendor / Product",
        "description": "Queries the embedded CVE database for known vulnerabilities "
                       "matching a target's vendor, product, version or raw banner. "
                       "Classifies each CVE as REMOTE (exploitable in-tree via wxf), LOCAL or "
                       "PHYSICAL. Lists mapped WirelessXPL-Forge modules when present. "
                       "Use after banner grabbing or service discovery to enumerate "
                       "attack surface.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/",
            "https://cve.mitre.org/",
            "https://www.exploit-db.com/",
        ),
        "devices": (
            "Wireless lab - subset emphasises 802.11/WPA/WPA3/BLE-adjacent CVE strings",
        ),
    }

    vendor = OptString("", "Target vendor (e.g. cisco, tplink, netgear, mikrotik, fortinet)")
    product = OptString("", "Target product/model (e.g. r7000, archer_c9, routeros, fortigate)")
    version = OptString("", "Target firmware/software version (optional, narrows results)")
    banner = OptString("", "Raw banner text from service scan (alternative to vendor+product)")
    remote_only = OptBool(False, "Show only remotely exploitable CVEs")
    show_physical = OptBool(True, "Include LOCAL/PHYSICAL CVEs in output (marked as non-exploitable)")

    def run(self):
        db = CVEDatabase()

        # Show database stats
        stats = db.summary()
        print_status("CVE Database: {} entries | {} remote | {} with wxf module | {} vendors".format(
            stats["total_cves"],
            stats["remote"],
            stats["exploitable_by_rxf"],
            stats["vendors_covered"],
        ))
        print_status("")

        if not self.vendor and not self.product and not self.banner:
            print_error("Set at least one of: vendor, product, or banner")
            print_info("Example: set vendor netgear")
            print_info("Example: set banner 'NETGEAR R7000'")
            return

        filter_remote = self.remote_only
        if not self.show_physical:
            filter_remote = True

        results = db.lookup(
            vendor=self.vendor,
            product=self.product,
            version=self.version,
            banner=self.banner,
            remote_only=filter_remote,
        )

        if not results:
            print_error("No CVEs found matching the criteria.")
            print_info("Try broader terms or check spelling.")
            return

        # Classify results
        remote_exploitable = [e for e in results if e.is_exploitable_by_rxf]
        remote_no_module = [e for e in results if e.is_remote and not e.is_exploitable_by_rxf]
        non_remote = [e for e in results if not e.is_remote]

        print_status(f"--- CVE Results ({len(results)} total) ---")
        print_status("")

        if remote_exploitable:
            print_success(f"=== EXPLOITABLE by WirelessXPL-Forge ({len(remote_exploitable)}) ===")
            print_status("")
            for entry in remote_exploitable:
                self._print_entry(entry, "EXPLOIT")
            print_status("")

        if remote_no_module:
            print_status(f"=== REMOTE - no wxf module yet ({len(remote_no_module)}) ===")
            print_status("")
            for entry in remote_no_module:
                self._print_entry(entry, "REMOTE")
            print_status("")

        if non_remote and self.show_physical:
            print_status(f"=== LOCAL/PHYSICAL access required ({len(non_remote)}) ===")
            print_info("  (WirelessXPL-Forge cannot exploit these remotely)")
            print_status("")
            for entry in non_remote:
                self._print_entry(entry, "PHYSICAL")
            print_status("")

        # Summary
        print_status("--- Summary ---")
        print_info(f"  Total CVEs matched:        {len(results)}")
        print_info(f"  Exploitable by wxf:        {len(remote_exploitable)}")
        print_info(f"  Remote (no module yet):    {len(remote_no_module)}")
        print_info(f"  Local/Physical only:       {len(non_remote)}")

        if remote_exploitable:
            print_status("")
            print_success("Quick exploit commands:")
            for entry in remote_exploitable:
                print_info("  use {}".format(entry.rxf_module.replace("/", os.sep) if hasattr(os, 'sep') else entry.rxf_module))

    def _print_entry(self, entry, tag: str) -> None:
        """Print a single CVE entry with formatting."""
        if tag == "EXPLOIT":
            print_success(f"  {entry.cve_id} | CVSS {entry.cvss_score:.1f} | {entry.access_vector}")
        elif tag == "REMOTE":
            print_info(f"  {entry.cve_id} | CVSS {entry.cvss_score:.1f} | {entry.access_vector}")
        else:
            print_info(f"  {entry.cve_id} | CVSS {entry.cvss_score:.1f} | {entry.access_vector} (not remotely exploitable)")

        print_info("    Product: {} / {} | Versions: {}".format(
            entry.vendor, entry.product, entry.affected_versions or "all"))
        print_info(f"    {entry.description}")

        if entry.rxf_module:
            print_success(f"    Module: {entry.rxf_module}")

    @mute
    def check(self):
        db = CVEDatabase()
        return db.total > 0
