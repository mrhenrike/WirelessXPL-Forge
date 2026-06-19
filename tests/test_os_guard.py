#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Unit tests for wirelessxpl.core.os_guard.

Tests verify that:
- OSRequirement values are correctly defined.
- @requires_os correctly blocks incompatible OS platforms.
- @requires_os passes on compatible platforms.
- get_module_os_label returns correct short labels.
- Error messages are clear and actionable.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from wirelessxpl.core.os_guard import (
    OSIncompatibleError,
    OSRequirement,
    get_module_os_label,
    requires_os,
)


class TestOSRequirementEnum(unittest.TestCase):
    """Tests for the OSRequirement enum."""

    def test_values_exist(self) -> None:
        """All three requirement levels must exist."""
        self.assertEqual(OSRequirement.LINUX_ONLY.value, "linux_only")
        self.assertEqual(OSRequirement.LINUX_MAC.value, "linux_mac")
        self.assertEqual(OSRequirement.CROSS_PLATFORM.value, "cross_platform")


class TestRequiresOsDecorator(unittest.TestCase):
    """Tests for the @requires_os decorator."""

    def test_linux_only_passes_on_linux(self) -> None:
        """LINUX_ONLY module must not raise on Linux."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Linux"):
            @requires_os(OSRequirement.LINUX_ONLY)
            class Exploit:
                def __init__(self):
                    pass

            exploit = Exploit()  # Must not raise.
            self.assertIsNotNone(exploit)

    def test_linux_only_raises_on_windows(self) -> None:
        """LINUX_ONLY module must raise OSIncompatibleError on Windows."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Windows"):
            @requires_os(OSRequirement.LINUX_ONLY)
            class Exploit:
                def __init__(self):
                    pass

            with self.assertRaises(OSIncompatibleError) as ctx:
                Exploit()
            self.assertIn("Windows", str(ctx.exception))
            self.assertIn("Linux", str(ctx.exception))

    def test_linux_only_raises_on_darwin(self) -> None:
        """LINUX_ONLY module must raise OSIncompatibleError on macOS (Darwin)."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Darwin"):
            @requires_os(OSRequirement.LINUX_ONLY)
            class Exploit:
                def __init__(self):
                    pass

            with self.assertRaises(OSIncompatibleError):
                Exploit()

    def test_linux_mac_passes_on_linux(self) -> None:
        """LINUX_MAC module must not raise on Linux."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Linux"):
            @requires_os(OSRequirement.LINUX_MAC)
            class Exploit:
                def __init__(self):
                    pass

            Exploit()  # Must not raise.

    def test_linux_mac_passes_on_darwin(self) -> None:
        """LINUX_MAC module must not raise on macOS."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Darwin"):
            @requires_os(OSRequirement.LINUX_MAC)
            class Exploit:
                def __init__(self):
                    pass

            Exploit()  # Must not raise.

    def test_linux_mac_raises_on_windows(self) -> None:
        """LINUX_MAC module must raise OSIncompatibleError on Windows."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Windows"):
            @requires_os(OSRequirement.LINUX_MAC)
            class Exploit:
                def __init__(self):
                    pass

            with self.assertRaises(OSIncompatibleError):
                Exploit()

    def test_cross_platform_passes_on_windows(self) -> None:
        """CROSS_PLATFORM module must not raise on Windows."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Windows"):
            @requires_os(OSRequirement.CROSS_PLATFORM)
            class Exploit:
                def __init__(self):
                    pass

            Exploit()  # Must not raise.

    def test_cross_platform_passes_on_darwin(self) -> None:
        """CROSS_PLATFORM module must not raise on macOS."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Darwin"):
            @requires_os(OSRequirement.CROSS_PLATFORM)
            class Exploit:
                def __init__(self):
                    pass

            Exploit()  # Must not raise.

    def test_cross_platform_passes_on_linux(self) -> None:
        """CROSS_PLATFORM module must not raise on Linux."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Linux"):
            @requires_os(OSRequirement.CROSS_PLATFORM)
            class Exploit:
                def __init__(self):
                    pass

            Exploit()  # Must not raise.

    def test_function_decorator_linux_only(self) -> None:
        """@requires_os must work on functions, not just classes."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Windows"):
            @requires_os(OSRequirement.LINUX_ONLY)
            def run_attack():
                pass

            with self.assertRaises(OSIncompatibleError):
                run_attack()

    def test_os_requirement_attribute_set(self) -> None:
        """Decorated class must have _os_requirement attribute set."""
        @requires_os(OSRequirement.LINUX_ONLY)
        class Exploit:
            def __init__(self):
                pass

        self.assertEqual(Exploit._os_requirement, OSRequirement.LINUX_ONLY)

    def test_error_message_contains_suggestion(self) -> None:
        """Error message must contain a suggestion for fixing the issue."""
        with patch("wirelessxpl.core.os_guard._current_os", return_value="Windows"):
            @requires_os(OSRequirement.LINUX_ONLY)
            class Exploit:
                def __init__(self):
                    pass

            with self.assertRaises(OSIncompatibleError) as ctx:
                Exploit()
            self.assertIn("Kali Linux", str(ctx.exception))


class TestGetModuleOsLabel(unittest.TestCase):
    """Tests for get_module_os_label helper."""

    def test_linux_only_label(self) -> None:
        """LINUX_ONLY must return 'Lx'."""
        @requires_os(OSRequirement.LINUX_ONLY)
        class Exploit:
            def __init__(self):
                pass

        self.assertEqual(get_module_os_label(Exploit), "Lx")

    def test_linux_mac_label(self) -> None:
        """LINUX_MAC must return 'Lx/Mac'."""
        @requires_os(OSRequirement.LINUX_MAC)
        class Exploit:
            def __init__(self):
                pass

        self.assertEqual(get_module_os_label(Exploit), "Lx/Mac")

    def test_cross_platform_label(self) -> None:
        """CROSS_PLATFORM must return 'All'."""
        @requires_os(OSRequirement.CROSS_PLATFORM)
        class Exploit:
            def __init__(self):
                pass

        self.assertEqual(get_module_os_label(Exploit), "All")

    def test_undecorated_defaults_to_lx(self) -> None:
        """Undecorated class must default to 'Lx' (safe default for most WXF modules)."""
        class RawExploit:
            pass

        self.assertEqual(get_module_os_label(RawExploit), "Lx")


if __name__ == "__main__":
    unittest.main()
