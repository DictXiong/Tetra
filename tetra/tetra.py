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
from .dnsutils import (
    DNSRecord,
    RecordType,
    resolve_name_to_template,
    cross_compare,
    assert_cname_unique,
)
from .backends.cloudflare import CloudflareClient
from .backends.dnspod import DNSPodClient


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
        self.is_bottom = config["layer"] == "bottom"
        self.prefix = COMMENT_PREFIX_BOTTOM if self.is_bottom else COMMENT_PREFIX_TOP
        self.comment = COMMENT_B if self.is_bottom else COMMENT_T
        self.domain = domain
        self.config = config
        self.logger = logger
        self.logger.warning(
            f"Initializing Tetra for [%s] in [{'bottom' if self.is_bottom else 'top'}] layer (%s)",
            domain,
            self.comment,
        )
        if config["backend"] == "cloudflare":
            self.backend = CloudflareClient(domain, config["auth"], self.prefix, self.logger)
        else:
            self.backend = DNSPodClient(domain, config["auth"], self.prefix, self.logger)

    def _parse_bottom_records(self):
        ans = []
        if "hosts_from_exec" in self.config:
            self.config["hosts"] = read_from_exec(shlex.split(self.config["hosts_from_exec"])) + self.config.get("hosts", [])
        for host in self.config["hosts"]:
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
                                        f"{name}.{z}",
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
                                        f"{name}.{z}",
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
                            basename,
                            RecordType.CNAME,
                            f"{name}.{current_zone}.{self.domain}.",
                            TTL_NET,
                            comment=self.comment,
                        )
                    )
                    for zone in records:
                        ans.append(
                            DNSRecord(
                                f"{basename}{get_zone_suffix(zone)}",
                                RecordType.CNAME,
                                f"{name}.{zone}.{self.domain}.",
                                TTL_PERMA if "-v" in basename else TTL_NET,
                                comment=self.comment,
                            )
                        )
                    if "-v" in basename and mid_name.get("current", False):
                        network_name = basename.split("-v")[0]
                        ans.append(
                            DNSRecord(
                                network_name,
                                RecordType.CNAME,
                                f"{basename}.{self.domain}.",
                                TTL_NET,
                                comment=self.comment,
                            )
                        )
                        for zone in records:
                            ans.append(
                                DNSRecord(
                                    f"{network_name}{get_zone_suffix(zone)}",
                                    RecordType.CNAME,
                                    f"{basename}{get_zone_suffix(zone)}.{self.domain}.",
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
        bottom = self.config.get("bottom", "")
        ans = []
        if "domains_from_exec" in self.config:
            self.config["domains"] = read_from_exec(shlex.split(self.config["domains_from_exec"])) + self.config.get("domains", [])
        for name in self.config["domains"]:
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
                    if not value.endswith(".") and not value.endswith(bottom):
                        value += f".{bottom}"
                for i in name["names"]:
                    ans.append(
                        DNSRecord(
                            i,
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
                        cname,
                        RecordType.CNAME,
                        f"{name['names'][0]}.{self.domain}.",
                        TTL_TOP,
                        None,
                        self.comment,
                    )
                )

        # flatten cname on root
        root_cname = []
        root_cname_indeices = []
        for index, record in enumerate(ans):
            if record.type == RecordType.CNAME and record.name == "@":
                root_cname.append(record)
                root_cname_indeices.append(index)
        for i in reversed(root_cname_indeices):
            del ans[i]
        for record in root_cname:
            ans += resolve_name_to_template(record.content, record)
        # add tailing dot for cname
        for record in ans:
            if record.type == RecordType.CNAME and not record.content.endswith("."):
                record.content += "."
        # validate
        assert_cname_unique(ans)
        for i in ans:
            i.assert_valid()
        return ans

    def run(self):
        if self.is_bottom:
            pending = self._parse_bottom_records()
        else:
            pending = self._parse_top_records()
        self.logger.info("Parsed to total %i records", len(pending))
        old = self.backend.get_records()
        adding, updating, deleting = cross_compare(old, pending, args.force)
        # print info
        self.logger.info("Records to add: (%s)", "none" if not adding else len(adding))
        for i in adding:
            print(i)
        self.logger.info(
            "Records to update: (%s)", "none" if not updating else len(updating)
        )
        for i in updating:
            print(i)
        self.logger.info(
            "Records to delete: (%s)", "none" if not deleting else len(deleting)
        )
        for i in deleting:
            print(i)
        if not adding and not updating and not deleting:
            self.logger.warning("No changes to be made")
            return
        if args.dry_run:
            self.logger.warning("Dry run, no changes made")
            return
        print("Do you want to continue? [y/N]", end=" ")
        if input().lower() != "y":
            return
        self.backend.update_records(adding, updating, deleting)


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
