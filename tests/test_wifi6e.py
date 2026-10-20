"""Tests for wirelessxpl.core.wifi.wifi6e."""


from wirelessxpl.core.wifi.wifi6e import (
    Band,
    BSSColorAnalyzer,
    OFDMAProber,
    WiFi6ENetwork,
    WiFi6EScanner,
    WiFiGeneration,
)


class TestWiFi6ENetwork:
    def test_defaults(self) -> None:
        net = WiFi6ENetwork()
        assert net.ssid == ""
        assert net.band == Band.BAND_5GHZ
        assert net.generation == WiFiGeneration.WIFI_6
        assert net.security == "WPA3-SAE"
        assert net.pmf is True
        assert net.mlo is False

    def test_6ghz(self) -> None:
        net = WiFi6ENetwork(
            ssid="TestNet",
            frequency=6115,
            band=Band.BAND_6GHZ,
            generation=WiFiGeneration.WIFI_6E,
        )
        assert net.band == Band.BAND_6GHZ
        assert net.generation == WiFiGeneration.WIFI_6E


class TestWiFi6EScanner:
    def test_init(self) -> None:
        scanner = WiFi6EScanner("wlan1")
        assert scanner.interface == "wlan1"

    def test_parse_empty(self) -> None:
        scanner = WiFi6EScanner()
        result = scanner._parse_scan_results("")
        assert result == []

    def test_parse_single_bss(self) -> None:
        scanner = WiFi6EScanner()
        output = (
            "BSS aa:bb:cc:dd:ee:ff(on wlan0)\n"
            "\tfreq: 6115\n"
            "\tSSID: TestNet6E\n"
            "\tsignal: -50.00 dBm\n"
        )
        results = scanner._parse_scan_results(output)
        assert len(results) == 1
        assert results[0].ssid == "TestNet6E"
        assert results[0].band == Band.BAND_6GHZ
        assert results[0].generation == WiFiGeneration.WIFI_6E

    def test_parse_5ghz_network(self) -> None:
        scanner = WiFi6EScanner()
        output = (
            "BSS 11:22:33:44:55:66(on wlan0)\n"
            "\tfreq: 5180\n"
            "\tSSID: Office5G\n"
        )
        results = scanner._parse_scan_results(output)
        assert len(results) == 1
        assert results[0].band == Band.BAND_5GHZ

    def test_build_network_2_4ghz(self) -> None:
        scanner = WiFi6EScanner()
        net = scanner._build_network({"bssid": "aa:bb", "freq": "2412", "SSID": "Home"})
        assert net.band == Band.BAND_2_4GHZ


class TestBSSColorAnalyzer:
    def test_no_collisions(self) -> None:
        nets = [
            WiFi6ENetwork(bssid="aa", channel=1, bss_color=1),
            WiFi6ENetwork(bssid="bb", channel=1, bss_color=2),
        ]
        analyzer = BSSColorAnalyzer()
        assert analyzer.detect_collisions(nets) == []

    def test_collision_detected(self) -> None:
        nets = [
            WiFi6ENetwork(bssid="aa", channel=36, bss_color=5),
            WiFi6ENetwork(bssid="bb", channel=36, bss_color=5),
        ]
        analyzer = BSSColorAnalyzer()
        collisions = analyzer.detect_collisions(nets)
        assert len(collisions) == 1
        assert collisions[0].color == 5
        assert len(collisions[0].networks) == 2

    def test_different_channels(self) -> None:
        nets = [
            WiFi6ENetwork(bssid="aa", channel=36, bss_color=5),
            WiFi6ENetwork(bssid="bb", channel=40, bss_color=5),
        ]
        analyzer = BSSColorAnalyzer()
        assert analyzer.detect_collisions(nets) == []

    def test_zero_color_ignored(self) -> None:
        nets = [
            WiFi6ENetwork(bssid="aa", channel=1, bss_color=0),
            WiFi6ENetwork(bssid="bb", channel=1, bss_color=0),
        ]
        analyzer = BSSColorAnalyzer()
        assert analyzer.detect_collisions(nets) == []


class TestOFDMAProber:
    def test_probe_returns_dict(self) -> None:
        prober = OFDMAProber()
        result = prober.probe("aa:bb:cc:dd:ee:ff")
        assert result["target"] == "aa:bb:cc:dd:ee:ff"
        assert "ofdma_dl" in result
        assert "mu_mimo_dl" in result
