#!/usr/bin/env python3

import os
import yaml
import enum
import time
import argparse
import logging
from tqdm import tqdm
import CloudFlare
import ipaddress

parser = argparse.ArgumentParser(description='Cloudflare API client')
parser.add_argument('--config', help='Path to the configuration file', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml'))
parser.add_argument('-D', '--dry-run', help='Do not make any changes', action='store_true')
parser.add_argument('-f', '--force', help='Force update', action='store_true')
args = parser.parse_args()

TTL_HOST = 43200
TTL_PREST = 86400
TTL_EXT = 1
TTL_NET = 1
COMMENT_PREFIX = 'CFCLI'
COMMENT = f'{COMMENT_PREFIX} {time.strftime("%Y-%m-%d %H:%M:%S")}'
ZONE_SUFFIX = {
    0: '',
    1: '-ext',
    4: '-ip4',
    6: '-ip6'
}

class RecordType(enum.Enum):
    A = 'A'
    AAAA = 'AAAA'
    CNAME = 'CNAME'
    def __str__(self):
        return self.value

class DNSRecord:
    def __init__(self, name, type, content, ttl, comment=None, id=None) -> None:
        self.name = name
        self.type = type
        self.content = content
        self.ttl = ttl
        self.comment = comment if comment else COMMENT
        self.id = id

    def __str__(self):
        return f'{self.name:28} IN {self.type:5} {self.content:39} {self.ttl}'

    def __eq__(self, __value: object) -> bool:
        return self.name == __value.name and self.type == __value.type and self.content == __value.content and self.ttl == __value.ttl

    def sims(self, __value: object) -> bool:
        return self.name == __value.name and self.type == __value.type

class CloudflareClient:
    def __init__(self, domain:str, config:dict):
        logging.info(f'Initializing Cloudflare client for {domain}')
        self.domain = domain
        self.config = config
        logging.info(f"Connecting to Cloudflare API")
        self.cf = CloudFlare.CloudFlare(token=self.config['token'])
        logging.info(f"Getting zone ID for {domain}")
        try:
            zones = self.cf.zones.get(params = {'name': domain})
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            exit(f'Error: {e}')
        if len(zones) != 1:
            exit(f'Error: {len(zones)} zones found for {domain}')
        self.zone_id = zones[0]['id']
        logging.info("Initialization done")

    def parse_hosts(self):
        ans = []
        for host in self.config['hosts']:
            has_ext = False
            has_ip4 = False
            has_ip6 = False
            name = host['name']
            ext_records = []
            if 'addresses' in host:
                if isinstance(host['addresses'], str):
                    host['addresses'] = [host['addresses']]
                for address in host['addresses']:
                    try:
                        tmp = ipaddress.ip_address(address)
                    except ValueError:
                        exit(f'Error: {address} is not a valid IP address')
                    if tmp.version == 4:
                        has_ip4 = True
                        ans.append(DNSRecord(f"{name}.0.{self.domain}", RecordType.A, address, TTL_HOST))
                        ext_records.append(DNSRecord(f"{name}.1.{self.domain}", RecordType.A, address, TTL_HOST))
                        ans.append(DNSRecord(f"{name}.4.{self.domain}", RecordType.A, address, TTL_HOST))
                    else:
                        has_ip6 = True
                        ans.append(DNSRecord(f"{name}.0.{self.domain}", RecordType.AAAA, address, TTL_HOST))
                        ext_records.append(DNSRecord(f"{name}.1.{self.domain}", RecordType.AAAA, address, TTL_HOST))
                        ans.append(DNSRecord(f"{name}.6.{self.domain}", RecordType.AAAA, address, TTL_HOST))
            if 'ext_addresses' in host:
                if isinstance(host['ext_addresses'], str):
                    host['ext_addresses'] = [host['ext_addresses']]
                if host['ext_addresses']:
                    ans += ext_records
                for address in host['ext_addresses']:
                    try:
                        tmp = ipaddress.ip_address(address)
                    except ValueError:
                        exit(f'Error: {address} is not a valid IP address')
                    has_ext = True
                    if tmp.version == 4:
                        has_ip4 = True
                        ans.append(DNSRecord(f"{name}.1.{self.domain}", RecordType.AAAA, address, TTL_EXT))
                        ans.append(DNSRecord(f"{name}.4.{self.domain}", RecordType.A, address, TTL_EXT))
                    else:
                        has_ip6 = True
                        ans.append(DNSRecord(f"{name}.1.{self.domain}", RecordType.AAAA, address, TTL_EXT))
                        ans.append(DNSRecord(f"{name}.6.{self.domain}", RecordType.AAAA, address, TTL_EXT))
            if 'mid_names' in host:
                if isinstance(host['mid_names'], str):
                    host['mid_names'] = [host['mid_names']]
                for mid_name in host['mid_names']:
                    if isinstance(mid_name, str):
                        mid_name = {'name': mid_name, 'current': False}
                    basename = mid_name['name']
                    if '-v' in basename:
                        ans.append(DNSRecord(f"{basename}.{self.domain}", RecordType.CNAME, f"{name}.0.{self.domain}", TTL_PREST))
                        if has_ext:
                            ans.append(DNSRecord(f"{basename}-ext.{self.domain}", RecordType.CNAME, f"{name}.1.{self.domain}", TTL_PREST))
                        if has_ip4:
                            ans.append(DNSRecord(f"{basename}-ip4.{self.domain}", RecordType.CNAME, f"{name}.4.{self.domain}", TTL_PREST))
                        if has_ip6:
                            ans.append(DNSRecord(f"{basename}-ip6.{self.domain}", RecordType.CNAME, f"{name}.6.{self.domain}", TTL_PREST))
                        if mid_name.get('current', False):
                            current_zone = mid_name.get('current_zone', 0)
                            network_name = basename.split('-v')[0]
                            ans.append(DNSRecord(f"{network_name}.{self.domain}", RecordType.CNAME, f"{basename}{ZONE_SUFFIX[current_zone]}.{self.domain}", TTL_NET))
                    else:
                        current_zone = mid_name.get('current_zone', 0)
                        ans.append(DNSRecord(f"{basename}.{self.domain}", RecordType.CNAME, f"{name}.{current_zone}.{self.domain}", TTL_NET))
        # validate
        names = [record.name for record in ans]
        for record in ans:
            assert record.name.endswith(self.domain)
            if record.type == RecordType.CNAME:
                assert len([i for i in names if i == record.name]) == 1, f"Error: {record.name} is not unique"
        return ans

    def get_cf_records(self) -> list:
        try:
            dns_records = self.cf.zones.dns_records.get(self.zone_id)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            exit(f'Error: {e}')
        cf_records = []
        for record in dns_records:
            if record['comment'] and COMMENT_PREFIX in record['comment']:
                if record['type'] == 'A':
                    type = RecordType.A
                elif record['type'] == 'AAAA':
                    type = RecordType.AAAA
                elif record['type'] == 'CNAME':
                    type = RecordType.CNAME
                else:
                    exit(f'Error: {record["type"]} is not a valid record type')
                cf_records.append(DNSRecord(record['name'], type, record['content'], record['ttl'], record['comment'], record['id']))
        return cf_records

    def update_dns(self, records):
        pending_records = [i for i in records]
        cf_records = self.get_cf_records()
        # identical records
        to_delete = []
        for index,record in enumerate(pending_records):
            if record in cf_records:
                cf_index = cf_records.index(record)
                if args.force:
                    logging.debug(f"Forcing updating '{record.name}'")
                    record.id = cf_records[cf_index].id
                else:
                    to_delete.append(index)
                del cf_records[cf_index]
        for index in reversed(to_delete):
            del pending_records[index]
        # updating records
        for index,record in enumerate(pending_records):
            for cf_record in cf_records:
                if record.sims(cf_record):
                    logging.debug(f"Updating '{record.name}' from '{cf_record.content}' ({type(cf_record.content)}) to '{record.content}' ({type(record.content)})")
                    record.id = cf_record.id
                    cf_records.remove(cf_record)
                    break
        # staging
        adding_records = [i for i in pending_records if i.id == None]
        updating_records = [i for i in pending_records if i.id != None]
        deleting_records = [i for i in cf_records]
        # print info
        logging.warning(f"Records to add: ({'none' if not adding_records else len(adding_records)})")
        for i in adding_records:
            print(i)
        logging.warning(f"Records to update: ({'none' if not updating_records else len(updating_records)})")
        for i in updating_records:
            print(i)
        logging.warning(f"Records to delete: ({'none' if not deleting_records else len(deleting_records)})")
        for i in deleting_records:
            print(i)
        # adding records
        if args.dry_run:
            logging.warning("Dry run, no changes made")
            return
        print("Do you want to continue? [y/N]")
        if input().lower() != 'y':
            exit("Aborted")
        with tqdm(total=len(adding_records)+len(updating_records)+len(deleting_records)) as pbar:
            for record in updating_records:
                try:
                    self.cf.zones.dns_records.put(self.zone_id, record.id, data={'name': record.name, 'type': str(record.type), 'content': record.content, 'ttl': record.ttl, 'comment': record.comment, 'proxied': False})
                except CloudFlare.exceptions.CloudFlareAPIError as e:
                    exit(f'Error: {e}')
                pbar.update(1)
            for record in deleting_records:
                try:
                    self.cf.zones.dns_records.delete(self.zone_id, record.id)
                except CloudFlare.exceptions.CloudFlareAPIError as e:
                    exit(f'Error: {e}')
                pbar.update(1)
            for record in adding_records:
                try:
                    self.cf.zones.dns_records.post(self.zone_id, data={'name': record.name, 'type': str(record.type), 'content': record.content, 'ttl': record.ttl, 'comment': record.comment, 'proxied': False})
                except CloudFlare.exceptions.CloudFlareAPIError as e:
                    exit(f'Error: {e}')
                pbar.update(1)

    def run(self):
        records = self.parse_hosts()
        logging.info(f"Parsed {len(records)} records")
        self.update_dns(records)
        
if __name__ == '__main__':
    logging.warning(COMMENT)
    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)
    for domain,domain_config in config.items():
        client = CloudflareClient(domain, domain_config)
        client.run()
