import copy
import logging
import sys
import unittest

from tetra.dnsutils import RecordType

sys.argv = ["tetra"]
from tetra.tetra import Tetra


class SubdomainTest(unittest.TestCase):
    def setUp(self):
        self.client = Tetra.__new__(Tetra)
        self.client.domain = "bd.dn42"
        self.client.root_config = {
            "backend": "powerdns",
            "auth": {"api_key": "test"},
            "subdomains": {
                "net": {"layer": "bottom"},
                "i": {"layer": "top"},
            },
        }
        self.client.subdomains = self.client.root_config["subdomains"]
        self.client.logger = logging.getLogger("test-subdomains")

    def test_subdomain_labels_are_appended_to_record_names(self):
        self.client._set_context(
            {
                "layer": "bottom",
                "hosts": [
                    {
                        "name": "host-v0",
                        "addresses": {"42": ["172.21.123.66"]},
                        "mid_names": [{"name": "sir0-v0", "current": True}],
                    }
                ],
            },
            "net",
        )
        records = self.client._parse_bottom_records()
        self.assertIn("host-v0.42.net", [record.name for record in records])
        self.assertIn("sir0-v0.net", [record.name for record in records])

    def test_powerdns_automatic_ttl_is_mapped_to_seconds(self):
        config = {
            "layer": "bottom",
            "hosts": [
                {
                    "name": "host-v0",
                    "addresses": {"42": ["172.21.123.66"]},
                    "mid_names": ["sir0-v0"],
                }
            ],
        }
        records = self.client._parse_subdomain(config, "net")
        self.assertNotIn(1, {record.ttl for record in records})
        self.assertIn(300, {record.ttl for record in records})

    def test_powerdns_line_specific_record_is_rejected_before_planning(self):
        config = {
            "layer": "top",
            "bottom": "net.bd.dn42",
            "domains": [
                {
                    "names": "line-specific",
                    "records": {"value": "target", "line": "telecom"},
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "line-specific"):
            self.client._parse_subdomain(config, "i")

    def test_top_root_cname_is_flattened_from_bottom_records(self):
        self.client._set_context(
            {
                "layer": "bottom",
                "hosts": [
                    {
                        "name": "host-v0",
                        "addresses": {"42": ["172.21.123.66"]},
                        "mid_names": [{"name": "sir0-v0", "current": False}],
                    }
                ],
            },
            "net",
        )
        self.client.available_records = self.client._parse_bottom_records()
        self.client._set_context(
            {
                "layer": "top",
                "bottom": "net.bd.dn42",
                "domains": [{"names": "@", "records": "sir0-v0"}],
            },
            "i",
        )
        records = self.client._parse_top_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].name, "i")
        self.assertEqual(records[0].type, RecordType.A)
        self.assertEqual(records[0].content, "172.21.123.66")

    def test_generated_and_static_entries_are_combined(self):
        self.client._set_context(
            {
                "layer": "top",
                "bottom": "net.bd.dn42",
                "domains_from_exec": "printf '[{\"names\": \"generated\", \"records\": \"sir0-v0\"}]'",
                "domains": [{"names": "manual", "records": "sir0-v0"}],
            },
            "i",
        )
        records = self.client._parse_top_records()
        self.assertEqual({record.name for record in records}, {"generated.i", "manual.i"})

    def test_short_bottom_name_is_rejected(self):
        self.client._set_context(
            {
                "layer": "top",
                "bottom": "net",
                "domains": [],
            },
            "i",
        )
        with self.assertRaisesRegex(ValueError, "complete domain name"):
            self.client._parse_top_records()

    def test_bottom_suffix_matching_uses_a_dns_label_boundary(self):
        self.client._set_context(
            {
                "layer": "top",
                "bottom": "net.bd.dn42",
                "domains": [{"names": "bad", "records": "notnet.bd.dn42"}],
            },
            "i",
        )
        records = self.client._parse_top_records()
        self.assertEqual(records[0].content, "notnet.bd.dn42.net.bd.dn42.")

    def test_overlapping_same_layer_subdomains_are_rejected(self):
        config = {
            "backend": "powerdns",
            "auth": {"api_key": "test"},
            "subdomains": {
                "net": {"layer": "bottom", "hosts": []},
                "child.net": {"layer": "bottom", "hosts": []},
            },
        }
        with self.assertRaisesRegex(ValueError, "Overlapping subdomain scopes"):
            Tetra("bd.dn42", config, logging.getLogger("test-subdomains"))

    def test_static_config_is_not_mutated_while_parsing(self):
        config = {
            "layer": "top",
            "bottom": "net.bd.dn42",
            "domains": [{"names": "one", "records": "target"}],
        }
        original = copy.deepcopy(config)
        self.client._set_context(config, "i")
        self.client._parse_top_records()
        self.assertEqual(config, original)


if __name__ == "__main__":
    unittest.main()
