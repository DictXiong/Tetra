import copy
import logging
import unittest

from tetra.backends.powerdns import PowerDNSClient
from tetra.dnsutils import DNSRecord, RecordType, is_managed_comment


class FakePowerDNSClient(PowerDNSClient):
    def __init__(self, zone):
        super().__init__(
            "bd.dn42",
            {"api_key": "test"},
            "TETRAB",
            logging.getLogger("test-powerdns"),
        )
        self.zone = copy.deepcopy(zone)
        self.patches = []

    def _request(self, method, path, payload=None):
        if method == "GET":
            return copy.deepcopy(self.zone)
        self.patches.append(payload)
        return None


ZONE = {
    "rrsets": [
        {
            "name": "sir0.42.bd.dn42.",
            "type": "A",
            "ttl": 600,
            "records": [{"content": "172.21.123.66", "disabled": False}],
            "comments": [{"content": "TETRAB managed"}],
        },
        {
            "name": "manual.42.bd.dn42.",
            "type": "A",
            "ttl": 600,
            "records": [{"content": "172.21.123.99", "disabled": False}],
            "comments": [],
        },
    ]
}


class PowerDNSTest(unittest.TestCase):
    def test_get_records_filters_unmanaged_rrsets(self):
        client = FakePowerDNSClient(ZONE)
        records = client.get_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].name, "sir0.42")
        self.assertEqual(records[0].type, RecordType.A)

    def test_update_replaces_the_complete_rrset(self):
        client = FakePowerDNSClient(ZONE)
        old = client.get_records()[0]
        updated = DNSRecord(
            old.name,
            old.type,
            "172.21.123.67",
            old.ttl,
            comment=old.comment,
            id=old.id,
        )
        client.update_records([], [updated], [])
        self.assertEqual(len(client.patches), 1)
        rrset = client.patches[0]["rrsets"][0]
        self.assertEqual(rrset["changetype"], "REPLACE")
        self.assertEqual(rrset["records"][0]["content"], "172.21.123.67")

    def test_updates_are_batched_and_non_tetra_comments_are_preserved(self):
        zone = copy.deepcopy(ZONE)
        zone["rrsets"][0]["comments"].insert(
            0, {"content": "operator note", "account": "admin"}
        )
        zone["rrsets"].append(
            {
                "name": "sir1.42.bd.dn42.",
                "type": "A",
                "ttl": 600,
                "records": [{"content": "172.21.123.68", "disabled": False}],
                "comments": [{"content": "TETRAB managed"}],
            }
        )
        client = FakePowerDNSClient(zone)
        old = client.get_records()
        updated = [
            DNSRecord(
                record.name,
                record.type,
                "172.21.123.70" if record.name.startswith("sir0") else "172.21.123.71",
                record.ttl,
                comment=record.comment,
                id=record.id,
            )
            for record in old
        ]

        client.update_records([], updated, [])

        self.assertEqual(len(client.patches), 1)
        self.assertEqual(len(client.patches[0]["rrsets"]), 2)
        first_comments = client.patches[0]["rrsets"][0]["comments"]
        self.assertIn(
            {"content": "operator note", "account": "admin"}, first_comments
        )
        self.assertIn(
            {"content": "TETRAB managed", "account": ""}, first_comments
        )

    def test_similar_comment_does_not_claim_ownership(self):
        self.assertFalse(is_managed_comment("NOT-TETRAB managed", "TETRAB"))
        self.assertFalse(is_managed_comment("TETRAB-legacy", "TETRAB"))
        self.assertTrue(is_managed_comment("TETRAB managed", "TETRAB"))

        zone = copy.deepcopy(ZONE)
        zone["rrsets"][0]["comments"] = [{"content": "NOT-TETRAB managed"}]
        self.assertEqual(FakePowerDNSClient(zone).get_records(), [])

    def test_disabled_managed_record_is_rejected(self):
        zone = copy.deepcopy(ZONE)
        zone["rrsets"][0]["records"][0]["disabled"] = True
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            FakePowerDNSClient(zone).get_records()

    def test_conflicting_tetra_owners_are_rejected(self):
        zone = copy.deepcopy(ZONE)
        zone["rrsets"][0]["comments"].append({"content": "TETRAT managed"})
        with self.assertRaisesRegex(RuntimeError, "conflicting Tetra owners"):
            FakePowerDNSClient(zone).get_records()

    def test_remote_plaintext_api_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, "plaintext HTTP"):
            PowerDNSClient(
                "bd.dn42",
                {"api_url": "http://192.0.2.1:8081", "api_key": "test"},
                "TETRAB",
                logging.getLogger("test-powerdns"),
            )

    def test_unmanaged_rrset_is_not_modified(self):
        client = FakePowerDNSClient(ZONE)
        with self.assertRaisesRegex(RuntimeError, "unmanaged"):
            client.update_records(
                [DNSRecord("manual.42", RecordType.A, "172.21.123.100", 600)],
                [],
                [],
            )


if __name__ == "__main__":
    unittest.main()
