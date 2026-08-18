#!/usr/bin/env python3

import os
import time
import logging
import argparse
import subprocess
import shlex
import ipaddress
import yaml
import json
import copy
from .dnsutils import (
    DNSRecord,
    RecordType,
    resolve_name_to_template,
    cross_compare,
    assert_cname_unique,
)
from .backends.cloudflare import CloudflareClient
from .backends.dnspod import DNSPodClient
from .backends.powerdns import PowerDNSClient


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    template = "%(levelname)s: %(message)s"

    FORMATS = {
        logging.DEBUG: grey + template + reset,
        logging.INFO: grey + template + reset,
        logging.WARNING: yellow + template + reset,
        logging.ERROR: red + template + reset,
        logging.CRITICAL: bold_red + template + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


parser = argparse.ArgumentParser(description="Tetra DNS Record Manager")
parser.add_argument("-c", "--config", default="tetra.yaml", help="Path to the configuration file")
parser.add_argument(
    "-d",
    "--domain",
    help="Domain to update (all in default)",
    default=None,
    action="append",
)
parser.add_argument(
    "-D", "--dry-run", help="Do not make any changes", action="store_true"
)
parser.add_argument('-v', '--verbose', help='Show more log', action='store_true')
parser.add_argument("-f", "--force", help="Force update", action="store_true")
args = parser.parse_args()


TTL_HOST = 43200
TTL_PERMA = 86400
TTL_EXT = 1  # 1 means auto
TTL_NET = 1
TTL_TOP = 600
COMMENT_PREFIX_BOTTOM = "TETRAB"
COMMENT_PREFIX_TOP = "TETRAT"
COMMENT_SUFFIX = f' {time.strftime("%Y-%m-%d %H:%M:%S")}'
COMMENT_B = COMMENT_PREFIX_BOTTOM + COMMENT_SUFFIX
COMMENT_T = COMMENT_PREFIX_TOP + COMMENT_SUFFIX
ZONE_SUFFIX = {0: "-phy", 1: "-ext", 4: "-ip4", 6: "-ip6"}


def get_zone_suffix(zone: int):
    if zone in ZONE_SUFFIX:
        return ZONE_SUFFIX[zone]
    if zone >= 10:
        return f"-z{zone}"
    raise ValueError(f"Invalid zone {zone}")


def read_from_exec(args):
    try:
        result = subprocess.run(
            args,
            check = True,
            text = True,
            capture_output = True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error executing:", e.stderr)
        exit(-1)
    except json.JSONDecodeError as e:
        print("Error decoding json:", e)
        exit(-1)


class Tetra:
    def __init__(self, domain, config, logger) -> None:
        self.domain = self._validate_domain_name(domain, "domain")
        if not isinstance(config, dict):
            raise ValueError(f"Configuration for {self.domain} must be a mapping")
        self.root_config = config
        self.config = config
        self.subdomain = None
        self.subdomains = config.get("subdomains", {})
        self.available_records = []
        self.logger = logger
        backend = config.get("backend")
        if backend not in ["cloudflare", "dnspod", "powerdns"]:
            raise ValueError(f"Unsupported Tetra backend: {backend!r}")
        if not isinstance(config.get("auth"), dict):
            raise ValueError(f"Configuration for {self.domain} must contain an auth mapping")
        if not isinstance(self.subdomains, dict):
            raise ValueError("subdomains must be a mapping")
        self.logger.warning(
            "Initializing Tetra for [%s] with %i layer configuration(s)",
            domain,
            len(self.subdomains) if self.subdomains else 1,
        )
        normalized_subdomains = {}
        for subdomain, subdomain_config in self.subdomains.items():
            normalized = self._validate_relative_name(
                subdomain, "subdomain", allow_root=False
            )
            if not isinstance(subdomain_config, dict):
                raise ValueError(
                    f"Configuration for subdomain {subdomain!r} must be a mapping"
                )
            self._validate_layer(subdomain_config, f"subdomain {subdomain!r}")
            normalized_subdomains[normalized] = subdomain_config
        names = list(normalized_subdomains)
        for index, name in enumerate(names):
            for other in names[index + 1 :]:
                same_layer = (
                    normalized_subdomains[name]["layer"]
                    == normalized_subdomains[other]["layer"]
                )
                if same_layer and (
                    name.endswith("." + other) or other.endswith("." + name)
                ):
                    raise ValueError(
                        f"Overlapping subdomain scopes are unsafe: {name!r} and {other!r}"
                    )
        self.subdomains = normalized_subdomains
        if not self.subdomains:
            self._validate_layer(config, f"domain {self.domain!r}")

    @staticmethod
    def _validate_layer(config, location):
        if config.get("layer") not in {"bottom", "top"}:
            raise ValueError(f"{location} layer must be 'bottom' or 'top'")

    @staticmethod
    def _validate_relative_name(name, field, allow_root=True):
        if not isinstance(name, str) or not name:
            raise ValueError(f"{field} must be a non-empty relative DNS name")
        if name == "@":
            if allow_root:
                return name
            raise ValueError(f"{field} cannot be the zone root")
        if name.startswith(".") or name.endswith(".") or ".." in name:
            raise ValueError(f"{field} must be a relative DNS name, got {name!r}")
        encoded_length = 0
        for label in name.split("."):
            try:
                encoded = label.encode("idna")
            except UnicodeError as error:
                raise ValueError(f"Invalid {field} label {label!r}") from error
            if len(encoded) > 63:
                raise ValueError(f"{field} label is longer than 63 bytes: {label!r}")
            encoded_length += len(encoded) + 1
        if encoded_length > 254:
            raise ValueError(f"{field} is longer than 253 bytes")
        return name

    @classmethod
    def _validate_domain_name(cls, name, field):
        if not isinstance(name, str):
            raise ValueError(f"{field} must be a DNS name")
        normalized = name.rstrip(".")
        cls._validate_relative_name(normalized, field, allow_root=False)
        if "." not in normalized:
            raise ValueError(f"{field} must be a complete domain name, got {name!r}")
        return normalized

    def _make_backend(self):
        auth = self.root_config["auth"]
        backend = self.root_config["backend"]
        if backend == "cloudflare":
            return CloudflareClient(self.domain, auth, self.prefix, self.logger)
        if backend == "dnspod":
            return DNSPodClient(self.domain, auth, self.prefix, self.logger)
        return PowerDNSClient(self.domain, auth, self.prefix, self.logger)

    def _set_context(self, config, subdomain):
        self._validate_layer(
            config, f"subdomain {subdomain!r}" if subdomain else "domain"
        )
        self.config = config
        self.subdomain = subdomain
        self.is_bottom = config["layer"] == "bottom"
        self.prefix = COMMENT_PREFIX_BOTTOM if self.is_bottom else COMMENT_PREFIX_TOP
        self.comment = COMMENT_B if self.is_bottom else COMMENT_T

    def _qualify_name(self, name):
        name = self._validate_relative_name(name, "record name")
        if self.subdomain is None:
            return name
        if name == "@":
            return self.subdomain
        return f"{name}.{self.subdomain}"

    def _fqdn(self, name):
        if name == "@":
            return self.domain + "."
        self._validate_relative_name(name, "record name", allow_root=False)
        return f"{name.rstrip('.')}.{self.domain}."

    def _config_entries(self, config, key):
        """Return generated entries followed by entries written in config.

        Both the legacy top-level domain configuration and each subdomain use
        this same merge rule.  Keep the static entries last so they retain the
        existing ordering and can be used for small local overrides/additions.
        """
        generated = []
        source = config.get(f"{key}_from_exec")
        if source:
            generated = read_from_exec(shlex.split(source))
        configured = config.get(key, [])
        if configured is None:
            configured = []
        if not isinstance(generated, list) or not isinstance(configured, list):
            raise ValueError(f"{key} and {key}_from_exec must produce lists")
        return copy.deepcopy(generated + configured)

    def _resolve_name_to_template(self, domain, template):
        target = domain.rstrip(".")

        def resolve(name, visited):
            if name in visited:
                raise ValueError(f"CNAME loop while resolving {domain}")
            visited = visited | {name}
            records = [
                record
                for record in self.available_records
                if self._fqdn(record.name).rstrip(".") == name
            ]
            resolved = []
            for record in records:
                if record.type in [RecordType.A, RecordType.AAAA]:
                    item = copy.deepcopy(template)
                    item.type = record.type
                    item.content = record.content
                    resolved.append(item)
                elif record.type == RecordType.CNAME:
                    resolved += resolve(record.content.rstrip("."), visited)
            return resolved

        if self.available_records:
            local = resolve(target, set())
            if local:
                return local
        return resolve_name_to_template(domain, template)

    def _parse_bottom_records(self):
        ans = []
        for host in self._config_entries(self.config, "hosts"):
            name = host["name"]
            records = {}
            if "addresses" in host:
                if isinstance(host["addresses"], str):
                    host["addresses"] = [host["addresses"]]
                if isinstance(host["addresses"], list):
                    host["addresses"] = {0: host["addresses"]}
                for zone, addresses in host["addresses"].items():
                    zone = int(zone)
                    if not addresses:
                        records[zone] = []
                        continue
                    if isinstance(addresses, str):
                        addresses = [addresses]
                    if zone < 10 and zone not in [0, 1]:
                        self.logger.fatal(
                            "special zone %s should not be set manually for name %s",
                            zone,
                            name,
                        )
                        exit(-1)
                    ttl = TTL_HOST if zone == 0 else TTL_EXT
                    for address in addresses:
                        try:
                            tmp = ipaddress.ip_address(address)
                        except ValueError:
                            self.logger.fatal("%s is not a valid IP address", address)
                            exit(-1)
                        zones = [zone]
                        if tmp.version == 4:
                            if zone == 0:
                                zones += [1, 4]
                            elif zone == 1:
                                zones += [4]
                            for z in zones:
                                if z not in records:
                                    records[z] = []
                                records[z].append(
                                    DNSRecord(
                                        self._qualify_name(f"{name}.{z}"),
                                        RecordType.A,
                                        address,
                                        ttl,
                                        comment=self.comment,
                                    )
                                )
                        else:
                            if zone == 0:
                                zones += [1, 6]
                            elif zone == 1:
                                zones += [6]
                            for z in zones:
                                if z not in records:
                                    records[z] = []
                                records[z].append(
                                    DNSRecord(
                                        self._qualify_name(f"{name}.{z}"),
                                        RecordType.AAAA,
                                        address,
                                        ttl,
                                        comment=self.comment,
                                    )
                                )
            if (
                0 in records
                and 1 in records
                and len(records[0]) == len(records[1]) != 0
            ):
                del records[1]
            for record in records.values():
                ans += record
            if "mid_names" in host:
                if isinstance(host["mid_names"], str):
                    host["mid_names"] = [host["mid_names"]]
                for mid_name in host["mid_names"]:
                    if isinstance(mid_name, str):
                        mid_name = {"name": mid_name, "current": False}
                    current_zone = mid_name.get("current_zone", sorted(records)[0])
                    basename = mid_name["name"]
                    ans.append(
                        DNSRecord(
                            self._qualify_name(basename),
                            RecordType.CNAME,
                            self._fqdn(self._qualify_name(f"{name}.{current_zone}")),
                            TTL_NET,
                            comment=self.comment,
                        )
                    )
                    for zone in records:
                        ans.append(
                            DNSRecord(
                                self._qualify_name(f"{basename}{get_zone_suffix(zone)}"),
                                RecordType.CNAME,
                                self._fqdn(self._qualify_name(f"{name}.{zone}")),
                                TTL_PERMA if "-v" in basename else TTL_NET,
                                comment=self.comment,
                            )
                        )
                    if "-v" in basename and mid_name.get("current", False):
                        network_name = basename.split("-v")[0]
                        ans.append(
                            DNSRecord(
                                self._qualify_name(network_name),
                                RecordType.CNAME,
                                self._fqdn(self._qualify_name(basename)),
                                TTL_NET,
                                comment=self.comment,
                            )
                        )
                        for zone in records:
                            ans.append(
                                DNSRecord(
                                    self._qualify_name(f"{network_name}{get_zone_suffix(zone)}"),
                                    RecordType.CNAME,
                                    self._fqdn(
                                        self._qualify_name(f"{basename}{get_zone_suffix(zone)}")
                                    ),
                                    TTL_NET,
                                    comment=self.comment,
                                )
                            )
        # add tailing dot for cname
        for record in ans:
            if record.type == RecordType.CNAME and not record.content.endswith("."):
                record.content += "."
        # validate
        assert_cname_unique(ans)
        for i in ans:
            i.assert_valid()
        return ans

    def _parse_top_records(self):
        bottom = self.config.get("bottom", "").rstrip(".")
        if bottom:
            bottom = self._validate_domain_name(bottom, "top-layer bottom")
        ans = []
        for name in self._config_entries(self.config, "domains"):
            if not isinstance(name["records"], list):
                name["records"] = [name["records"]]
            if not isinstance(name["names"], list):
                name["names"] = [name["names"]]
            for record in name["records"]:
                if isinstance(record, str):
                    record = {"value": record}
                value = record["value"]
                try:
                    if ipaddress.ip_address(value).version == 4:
                        record_type = RecordType.A
                    else:
                        record_type = RecordType.AAAA
                    self.logger.warning(
                        "%s is an IP address, please use CNAME instead",
                        value,
                    )
                except ValueError:
                    record_type = RecordType.CNAME
                    if not value.endswith("."):
                        if bottom and value != bottom and not value.endswith("." + bottom):
                            value += f".{bottom}"
                        value += "."
                for i in name["names"]:
                    ans.append(
                        DNSRecord(
                            self._qualify_name(i),
                            record_type,
                            value,
                            TTL_TOP,
                            record.get("line", None),
                            self.comment,
                        )
                    )
            cnamed_by = name.get("cnames", [])
            if isinstance(cnamed_by, str):
                cnamed_by = [cnamed_by]
            for cname in cnamed_by:
                ans.append(
                    DNSRecord(
                        self._qualify_name(cname),
                        RecordType.CNAME,
                        self._fqdn(self._qualify_name(name["names"][0])),
                        TTL_TOP,
                        None,
                        self.comment,
                    )
                )

        # flatten cname on root
        root_cname = []
        root_cname_indeices = []
        root_name = self._qualify_name("@")
        for index, record in enumerate(ans):
            if record.type == RecordType.CNAME and record.name == root_name:
                root_cname.append(record)
                root_cname_indeices.append(index)
        for i in reversed(root_cname_indeices):
            del ans[i]
        for record in root_cname:
            ans += self._resolve_name_to_template(record.content, record)
        # add tailing dot for cname
        for record in ans:
            if record.type == RecordType.CNAME and not record.content.endswith("."):
                record.content += "."
        # validate
        assert_cname_unique(ans)
        for i in ans:
            i.assert_valid()
        return ans

    def _parse_subdomain(self, config, subdomain):
        self._set_context(config, subdomain)
        records = (
            self._parse_bottom_records()
            if self.is_bottom
            else self._parse_top_records()
        )
        if self.root_config["backend"] == "powerdns":
            if any(record.line is not None for record in records):
                raise ValueError("PowerDNS backend does not support line-specific records")
            auto_ttl = self.root_config["auth"].get("auto_ttl", 300)
            if (
                not isinstance(auto_ttl, int)
                or isinstance(auto_ttl, bool)
                or auto_ttl <= 0
            ):
                raise ValueError("PowerDNS auto_ttl must be a positive integer")
            for record in records:
                if record.ttl == 1:
                    record.ttl = auto_ttl
        return records

    def _plan_subdomain(self, config, subdomain, pending, old_records):
        self._set_context(config, subdomain)
        self.logger.info(
            "Parsed %i records for %s.%s",
            len(pending),
            subdomain or "@",
            self.domain,
        )
        old = old_records
        if subdomain is not None:
            old = [
                record
                for record in old
                if record.name == subdomain or record.name.endswith(f".{subdomain}")
            ]
        adding, updating, deleting = cross_compare(old, pending, args.force)
        self.logger.info("Records to add: (%s)", "none" if not adding else len(adding))
        for record in adding:
            print(record)
        self.logger.info("Records to update: (%s)", "none" if not updating else len(updating))
        for record in updating:
            print(record)
        self.logger.info("Records to delete: (%s)", "none" if not deleting else len(deleting))
        for record in deleting:
            print(record)
        return adding, updating, deleting

    def run(self):
        configs = (
            list(self.subdomains.items()) if self.subdomains else [(None, self.root_config)]
        )
        parsed = []
        self.available_records = []
        for subdomain, config in configs:
            if config["layer"] == "bottom":
                pending = self._parse_subdomain(config, subdomain)
                self.available_records += pending
                parsed.append((subdomain, config, pending))
        for subdomain, config in configs:
            if config["layer"] != "bottom":
                pending = self._parse_subdomain(config, subdomain)
                parsed.append((subdomain, config, pending))
        backend_cache = {}
        old_records_cache = {}
        changes = {}
        for subdomain, config, pending in parsed:
            self._set_context(config, subdomain)
            backend = backend_cache.get(self.prefix)
            if backend is None:
                backend = self._make_backend()
                backend_cache[self.prefix] = backend
                old_records_cache[self.prefix] = backend.get_records()
            adding, updating, deleting = self._plan_subdomain(
                config,
                subdomain,
                pending,
                old_records_cache[self.prefix],
            )
            if adding or updating or deleting:
                combined = changes.setdefault(backend, [[], [], []])
                combined[0].extend(adding)
                combined[1].extend(updating)
                combined[2].extend(deleting)
        if not changes:
            self.logger.warning("No changes to be made")
            return
        if args.dry_run:
            self.logger.warning("Dry run, no changes made")
            return
        print("Do you want to continue? [y/N]", end=" ")
        if input().lower() != "y":
            return
        for backend, (adding, updating, deleting) in changes.items():
            backend.update_records(adding, updating, deleting)


def main():
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = logging.getLogger("tetra")
    logger.setLevel(log_level)
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    logger.warning("Tetra DNS Client Started")
    if not os.path.isfile(args.config):
        logger.fatal("A proper config file must be specified by `-c` or `--config`")
        exit(-1)
    with open(args.config, "r", encoding="utf-8") as file:
        config_file = yaml.safe_load(file)
    if args.domain:
        for domain in args.domain:
            Tetra(domain, config_file[domain], logger).run()
    else:
        for domain, config in config_file.items():
            Tetra(domain, config, logger).run()


if __name__ == "__main__":
    main()
