import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from ..dnsutils import DNSRecord, RecordType, is_managed_comment


SUPPORTED_TYPES = {RecordType.A, RecordType.AAAA, RecordType.CNAME}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the PowerDNS API key to a redirected origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_secret(auth: dict, key: str):
    key_file = key + "_file"
    if key_file in auth:
        with open(auth[key_file], "r", encoding="utf-8") as f:
            return f.read().strip()
    return auth[key]


class PowerDNSClient:
    """PowerDNS Authoritative API client.

    PowerDNS updates RRsets rather than individual records.  Tetra therefore
    treats an exact Tetra comment marker as ownership of the whole RRset and
    rejects existing RRsets without that marker before making any change.
    """

    def __init__(self, domain, auth, prefix, logger):
        self.domain = domain.rstrip(".")
        self.zone_name = self.domain + "."
        self.prefix = prefix
        self.logger = logger
        self.api_url = auth.get("api_url", "http://127.0.0.1:8081").rstrip("/")
        parsed_url = urllib.parse.urlsplit(self.api_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError(
                "PowerDNS api_url must be an HTTP(S) URL without credentials, "
                "query, or fragment"
            )
        if parsed_url.scheme == "http" and not auth.get("allow_insecure_http", False):
            try:
                is_loopback = ipaddress.ip_address(parsed_url.hostname).is_loopback
            except ValueError:
                is_loopback = parsed_url.hostname.lower() == "localhost"
            if not is_loopback:
                raise ValueError(
                    "Refusing to send the PowerDNS API key over remote plaintext HTTP; "
                    "use HTTPS or set allow_insecure_http explicitly"
                )
        self.server_id = auth.get("server_id", "localhost")
        self.api_key = get_secret(auth, "api_key")
        if not self.api_key:
            raise ValueError("PowerDNS api_key must not be empty")
        server_id = urllib.parse.quote(self.server_id, safe="")
        self.base_url = f"{self.api_url}/api/v1/servers/{server_id}"
        self._opener = urllib.request.build_opener(_NoRedirectHandler())
        self.logger.debug("PowerDNS client initialized")

    def _request(self, method, path, payload=None):
        body = None
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                data = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"PowerDNS API {method} {path} failed with HTTP {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(
                f"PowerDNS API {method} {path} failed: {error.reason}"
            ) from error
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    def _read_zone(self):
        zone = urllib.parse.quote(self.zone_name, safe="")
        return self._request("GET", f"/zones/{zone}")

    def _relative_name(self, name):
        name = name.rstrip(".")
        if name == self.domain:
            return "@"
        suffix = "." + self.domain
        if not name.endswith(suffix):
            raise ValueError(
                f"PowerDNS returned a record outside zone {self.domain}: {name}"
            )
        return name[: -len(suffix)]

    @staticmethod
    def _comments(rrset):
        comments = rrset.get("comments", [])
        return [
            item.get("content", "") if isinstance(item, dict) else str(item)
            for item in comments
        ]

    def _managed_comment(self, rrset):
        comments = self._comments(rrset)
        owners = {
            prefix
            for prefix in ("TETRAB", "TETRAT")
            if any(is_managed_comment(comment, prefix) for comment in comments)
        }
        if len(owners) > 1:
            name = rrset.get("name", "<unknown>")
            record_type = rrset.get("type", "<unknown>")
            raise RuntimeError(
                f"PowerDNS RRset {name} {record_type} has conflicting Tetra owners"
            )
        return next(
            (i for i in comments if is_managed_comment(i, self.prefix)), None
        )

    def _record_id(self, name, record_type, content, ttl, line=None):
        # PowerDNS has no record-level API id.  Keep the old value so updates
        # and deletes can identify the exact pre-change record in an RRset.
        return (name, record_type.value, content, ttl, line)

    def _parse_zone(self, zone):
        records = []
        rrsets = {}
        for rrset in zone.get("rrsets", []):
            try:
                record_type = RecordType(rrset["type"])
            except ValueError:
                continue
            if record_type not in SUPPORTED_TYPES:
                continue
            name = self._relative_name(rrset["name"])
            key = (name, record_type.value)
            rrsets[key] = rrset
            comment = self._managed_comment(rrset)
            if comment is None:
                continue
            if any(item.get("disabled", False) for item in rrset.get("records", [])):
                raise RuntimeError(
                    f"Refusing to manage disabled records in PowerDNS RRset {name} {record_type}"
                )
            ttl = int(rrset["ttl"])
            for item in rrset.get("records", []):
                content = item["content"]
                if record_type == RecordType.CNAME and not content.endswith("."):
                    content += "."
                record = DNSRecord(
                    name,
                    record_type,
                    content,
                    ttl,
                    comment=comment,
                    id=self._record_id(name, record_type, content, ttl),
                )
                record.assert_valid()
                records.append(record)
        return records, rrsets

    @staticmethod
    def _key(record):
        return (record.name, record.type.value)

    def get_records(self):
        self.logger.debug("Getting records for domain %s from PowerDNS", self.domain)
        records, _ = self._parse_zone(self._read_zone())
        self.logger.info(
            "Got %i Tetra records from PowerDNS zone %s", len(records), self.domain
        )
        return records

    def _assert_managed_or_new(self, key, rrsets):
        rrset = rrsets.get(key)
        if rrset is not None and self._managed_comment(rrset) is None:
            raise RuntimeError(
                f"Refusing to modify unmanaged PowerDNS RRset {key[0]} {key[1]}"
            )

    def _build_rrset_patch(self, name, record_type, records, comment, previous=None):
        fqdn = self.zone_name if name == "@" else f"{name}.{self.zone_name}"
        rrset = {
            "name": fqdn,
            "type": record_type.value,
            "changetype": "DELETE" if not records else "REPLACE",
        }
        if records:
            ttls = {record.ttl for record in records}
            if len(ttls) != 1:
                raise ValueError(f"PowerDNS RRset {name} {record_type} has mixed TTLs")
            rrset["ttl"] = records[0].ttl
            rrset["records"] = [
                {"content": record.content, "disabled": False} for record in records
            ]
            comments = []
            if previous is not None:
                for item in previous.get("comments", []):
                    content = (
                        item.get("content", "")
                        if isinstance(item, dict)
                        else str(item)
                    )
                    if is_managed_comment(content, self.prefix):
                        continue
                    preserved = {"content": content}
                    if isinstance(item, dict) and item.get("account") is not None:
                        preserved["account"] = item["account"]
                    comments.append(preserved)
            comments.append({"content": comment})
            rrset["comments"] = comments
        return rrset

    def update_records(self, adding, updating, deleting):
        if any(record.line is not None for record in adding + updating + deleting):
            raise ValueError("PowerDNS backend does not support line-specific records")

        zone = self._read_zone()
        current, rrsets = self._parse_zone(zone)
        by_key = {}
        for record in current:
            by_key.setdefault(self._key(record), []).append(record)
        changed = set()

        for record in adding:
            key = self._key(record)
            self._assert_managed_or_new(key, rrsets)
            by_key.setdefault(key, []).append(record)
            changed.add(key)

        for record in updating:
            key = self._key(record)
            self._assert_managed_or_new(key, rrsets)
            old_id = record.id
            candidates = by_key.get(key, [])
            index = next(
                (i for i, old in enumerate(candidates) if old.id == old_id), None
            )
            if index is None:
                raise RuntimeError(
                    f"PowerDNS record disappeared before update: {record.summary()}"
                )
            candidates[index] = record
            changed.add(key)

        for record in deleting:
            key = self._key(record)
            self._assert_managed_or_new(key, rrsets)
            candidates = by_key.get(key, [])
            index = next(
                (i for i, old in enumerate(candidates) if old.id == record.id), None
            )
            if index is None:
                raise RuntimeError(
                    f"PowerDNS record disappeared before delete: {record.summary()}"
                )
            del candidates[index]
            changed.add(key)

        patches = []
        for name, type_name in sorted(changed):
            key = (name, type_name)
            records = by_key.get(key, [])
            record_type = RecordType(type_name)
            comment = next((i.comment for i in records if i.comment), None)
            if comment is None and key in rrsets:
                comment = self._managed_comment(rrsets[key])
            if records and comment is None:
                raise RuntimeError(
                    f"Missing Tetra comment for PowerDNS RRset {name} {type_name}"
                )
            patches.append(
                self._build_rrset_patch(
                    name, record_type, records, comment, previous=rrsets.get(key)
                )
            )
        if patches:
            zone_path = urllib.parse.quote(self.zone_name, safe="")
            self._request("PATCH", f"/zones/{zone_path}", {"rrsets": patches})
