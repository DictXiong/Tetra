#!/usr/bin/env python3

import os
import yaml
import time
import logging
import argparse
import ipaddress
from dnsutils import DNSRecord, RecordType, resolve_name_to_template, cross_compare, assert_cname_unique, check_name_exist

parser = argparse.ArgumentParser(description='Tetra DNS Record Manager')
parser.add_argument('--config', help='Path to the configuration file',
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml'))
parser.add_argument('-d', '--domain', help='Domain to update (all in default)', default=None, action='append')
parser.add_argument('-D', '--dry-run',
                    help='Do not make any changes', action='store_true')
parser.add_argument('-f', '--force', help='Force update', action='store_true')
parser.add_argument('-v', '--verbose', help='Show more log', action='store_true')
args = parser.parse_args()
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(levelname)s: %(message)s')


TTL_HOST = 43200
TTL_PREST = 86400
TTL_EXT = 1  # 1 means auto
TTL_NET = 1
TTL_TOP = 600
COMMENT_PREFIX_BOTTOM = 'TETRAB'
COMMENT_PREFIX_TOP = 'TETRAT'
COMMENT_SUFFIX = f' {time.strftime("%Y-%m-%d %H:%M:%S")}'
COMMENT_B = COMMENT_PREFIX_BOTTOM + COMMENT_SUFFIX
COMMENT_T = COMMENT_PREFIX_TOP + COMMENT_SUFFIX
ZONE_SUFFIX = {
    0: '',
    1: '-ext',
    4: '-ip4',
    6: '-ip6'
}
def get_zone_suffix(zone:int):
    if zone in ZONE_SUFFIX: return ZONE_SUFFIX[zone]
    else: return f"-{zone}"


class Tetra:
    def __init__(self, domain, config) -> None:
        self.is_bottom = config['layer'] == "bottom"
        self.prefix = COMMENT_PREFIX_BOTTOM if self.is_bottom else COMMENT_PREFIX_TOP
        self.comment = COMMENT_B if self.is_bottom else COMMENT_T
        self.domain = domain
        self.config = config
        logging.warning(f"Initializing Tetra for [{domain}] in [{'bottom' if self.is_bottom else 'top'}] layer ({self.comment})")
        if config['backend'] == 'cloudflare':
            from backends.cloudflare import CloudflareClient
            self.backend = CloudflareClient(domain, config['auth'], self.prefix)
        else:
            from backends.dnspod import DNSPodClient
            self.backend = DNSPodClient(domain, config['auth'], self.prefix)

    def _parse_bottom_records(self):
        ans = []
        for host in self.config['hosts']:
            name = host['name']
            records = {}
            if 'addresses' in host:
                if isinstance(host['addresses'], str):
                    host['addresses'] = [host['addresses']]
                if isinstance(host['addresses'], list):
                    host['addresses'] = {0:host['addresses']}
                for zone,addresses in host['addresses'].items():
                    if isinstance(addresses, str):
                        addresses = [addresses]
                    if zone < 10 and zone not in [0,1]:
                        logging.warning(f"special zone {zone} should not be set manually for name {name}")
                    ttl = TTL_HOST if zone == 0 else TTL_EXT
                    for address in addresses:
                        try: tmp = ipaddress.ip_address(address)
                        except ValueError: exit(f'Error: {address} is not a valid IP address')
                        zones = [zone]
                        if tmp.version == 4:
                            if zone == 0: zones += [1,4]
                            elif zone == 1: zones += [4]
                            for z in zones:
                                if z not in records: records[z] = []
                                records[z].append(
                                    DNSRecord(f"{name}.{z}", RecordType.A, address, ttl, comment=self.comment)
                                )
                        else:
                            if zone == 0: zones += [1,6]
                            elif zone == 1: zones += [6]
                            for z in zones:
                                if z not in records: records[z] = []
                                records[z].append(
                                    DNSRecord(f"{name}.{z}", RecordType.AAAA, address, ttl, comment=self.comment)
                                )
            if 0 in records and 1 in records and len(records[0]) == len(records[1]):
                del records[1]
            for record in records.values():
                ans += record
            if 'mid_names' in host:
                if isinstance(host['mid_names'], str):
                    host['mid_names'] = [host['mid_names']]
                for mid_name in host['mid_names']:
                    if isinstance(mid_name, str):
                        mid_name = {'name': mid_name, 'current': False}
                    basename = mid_name['name']
                    if '-v' in basename:
                        for zone in records:
                            ans.append(
                                DNSRecord(f"{basename}{get_zone_suffix(zone)}", RecordType.CNAME, f"{name}.{zone}.{self.domain}.", TTL_PREST, comment=self.comment)
                            )
                        if mid_name.get('current', False):
                            current_zone = mid_name.get('current_zone', 0)
                            network_name = basename.split('-v')[0]
                            ans.append(
                                DNSRecord(f"{network_name}", RecordType.CNAME,f"{basename}{get_zone_suffix(current_zone)}.{self.domain}.", TTL_NET, comment=self.comment)
                            )
                    else:
                        current_zone = mid_name.get('current_zone', 0)
                        ans.append(DNSRecord(f"{basename}", RecordType.CNAME, f"{name}.{current_zone}.{self.domain}.", TTL_NET, comment=self.comment))
        # add tailing dot for cname
        for record in ans:
            if record.type == RecordType.CNAME and not record.content.endswith('.'):
                record.content += '.'
        # validate
        assert_cname_unique(ans)
        for i in ans:
            i.assert_valid()
        return ans

    def _parse_top_records(self):
        ans = []
        for name in self.config['domains']:
            if not isinstance(name['records'], list):
                name['records'] = [name['records']]
            if not isinstance(name['names'], list):
                name['names'] = [name['names']]
            for record in name['records']:
                if isinstance(record, str):
                    record = {'value': record}
                value = record['value']
                try:
                    if ipaddress.ip_address(value).version == 4:
                        type = RecordType.A
                    else:
                        type = RecordType.AAAA
                except ValueError:
                    type = RecordType.CNAME
                for i in name['names']:
                    ans.append(DNSRecord(i, type, value, TTL_TOP, record.get('line', '默认'), self.comment))
            cnamed_by = name.get('cnames', [])
            if isinstance(cnamed_by, str):
                cnamed_by = [cnamed_by]
            for cname in cnamed_by:
                ans.append(DNSRecord(cname, RecordType.CNAME, f"{name['names'][0]}.{self.domain}.", TTL_TOP, '默认', self.comment))

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
            if record.type == RecordType.CNAME and not record.content.endswith('.'):
                record.content += '.'
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
        old = self.backend.get_records()
        adding, updating, deleting = cross_compare(old, pending, args.force)
        # print info
        logging.info(
            f"Records to add: ({'none' if not adding else len(adding)})")
        for i in adding:
            print(i)
        logging.info(
            f"Records to update: ({'none' if not updating else len(updating)})")
        for i in updating:
            print(i)
        logging.info(
            f"Records to delete: ({'none' if not deleting else len(deleting)})")
        for i in deleting:
            print(i)
        if not adding and not updating and not deleting:
            logging.warning("No changes to be made")
            return
        if args.dry_run:
            logging.warning("Dry run, no changes made")
            return
        print("Do you want to continue? [y/N]", end=' ')
        if input().lower() != 'y':
            return
        self.backend.update_records(adding, updating, deleting)


if __name__ == "__main__":
    logging.warning(f'Tetra DNS Client Started')
    with open(args.config, 'r') as file:
        config_file = yaml.safe_load(file)
    if args.domain:
        for domain in args.domain:
            Tetra(domain, config_file[domain]).run()
    else:
        for domain,config in config_file.items():
            Tetra(domain, config).run()
