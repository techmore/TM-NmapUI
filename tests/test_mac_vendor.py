from nmapui.mac_vendor import (
    is_globally_administered_unicast_mac,
    is_locally_administered_mac,
    lookup_mac_vendor,
)


def test_lookup_mac_vendor_prefers_longest_nmap_prefix(tmp_path):
    database = tmp_path / "nmap-mac-prefixes"
    database.write_text(
        "# fixture\n001122 Acme Devices\n0011223 Acme Extended Systems\n",
        encoding="utf-8",
    )

    assert lookup_mac_vendor("00:11:22:AA:BB:CC", database_path=database) == "Acme Devices"
    assert lookup_mac_vendor("00:11:22:3A:BB:CC", database_path=database) == "Acme Extended Systems"


def test_lookup_skips_private_multicast_and_malformed_macs(tmp_path):
    database = tmp_path / "nmap-mac-prefixes"
    database.write_text("021122 Private Vendor\n011122 Multicast Vendor\n", encoding="utf-8")

    assert is_locally_administered_mac("02:11:22:33:44:55")
    assert not is_globally_administered_unicast_mac("02:11:22:33:44:55")
    assert lookup_mac_vendor("02:11:22:33:44:55", database_path=database) == ""
    assert not is_globally_administered_unicast_mac("01:11:22:33:44:55")
    assert lookup_mac_vendor("01:11:22:33:44:55", database_path=database) == ""
    assert lookup_mac_vendor("00:11:22:33:44:GG", database_path=database) == ""
