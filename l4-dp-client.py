#!/usr/bin/env python3

import os
import yaml
import enum
import time
import argparse
import logging
import copy
import dns.resolver
import dns.rdatatype
from tqdm import tqdm
from tencentcloud.common import credential
from tencentcloud.dnspod.v20210323 import dnspod_client, models
import ipaddress

parser = argparse.ArgumentParser(description='Cloudflare API client')
parser.add_argument('--config', help='Path to the configuration file',
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'l4-config.yaml'))
parser.add_argument('-D', '--dry-run',
                    help='Do not make any changes', action='store_true')
parser.add_argument('-f', '--force', help='Force update', action='store_true')
args = parser.parse_args()

TTL_DEFAULT = 600
COMMENT_PREFIX = 'CFCLI'
COMMENT = f'{COMMENT_PREFIX} {time.strftime("%Y-%m-%d %H:%M:%S")}'

class RecordType(enum.Enum):
    A = 'A'
    AAAA = 'AAAA'
    CNAME = 'CNAME'

    def __str__(self):
        return self.value


class DNSRecord:
    def __init__(self, name, type, content, ttl, line=None, comment=None, id=None) -> None:
        self.name = name
        self.type = type
        self.content = content
        self.ttl = ttl
        self.line = line
        self.comment = comment if comment else COMMENT
        self.id = id

    def assert_valid(self):
        if self.name.endswith('.'):
            raise ValueError("A record name should not end with a dot")
        if self.type == RecordType.CNAME:
            if self.name == '@':
                raise ValueError("Root CNAME is not allowed")
            if not self.content.endswith('.'):
                raise ValueError("CNAME content should end with a dot")
        if self.type == RecordType.A:
            addr = ipaddress.ip_address(self.content)
            if not addr.version == 4:
                raise ValueError("Invalid IPv4 address")
        if self.type == RecordType.AAAA:
            addr = ipaddress.ip_address(self.content)
            if not addr.version == 6:
                raise ValueError("Invalid IPv6 address")

    def __str__(self):
        self.assert_valid()
        return f'{self.name:23} {self.ttl:5}  IN  {self.type:5} {self.content:39}' + (f' [{self.line}]' if self.line else '') + (f' ; {self.comment}' if self.comment else '')

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, DNSRecord):
            return False
        return self.name == __value.name and self.type == __value.type and self.content == __value.content and self.ttl == __value.ttl and self.line == __value.line

    def sims(self, __value: object) -> bool:
        if not isinstance(__value, DNSRecord):
            return False
        return self.name == __value.name and self.type == __value.type

class DNSPodClient:
    def __init__(self, domain: str, config: dict):
        logging.info(f'Initializing DNSPod client for {domain}')
        self.domain = domain
        self.config = config
        logging.info(f"Connecting to DNSPod API")
        cred = credential.Credential(self.config['secret_id'], self.config['secret_key'])
        self.client = dnspod_client.DnspodClient(cred, "")
        logging.info("Initialization done")
    
    def get_records(self):
        logging.info(f"Getting records for domain {self.domain}")
        request = models.DescribeRecordListRequest()
        request.Domain = self.domain
        response = self.client.DescribeRecordList(request)
        ans = []
        for record in response.RecordList:
            if record.Remark and COMMENT_PREFIX in record.Remark:
                type = RecordType(record.Type)
                ans.append(DNSRecord(
                    record.Name, type, record.Value, record.TTL, record.Line, record.Remark, record.RecordId))
        return ans

    def parse_records(self):
        ans = []
        for name in self.config['dns']:
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
                    ans.append(DNSRecord(i, type, value, TTL_DEFAULT, record.get('line', '默认'), COMMENT))
            cnamed_by = name.get('cnames', [])
            if isinstance(cnamed_by, str):
                cnamed_by = [cnamed_by]
            for cname in cnamed_by:
                ans.append(DNSRecord(cname, RecordType.CNAME, f"{name['names'][0]}.{self.domain}.", TTL_DEFAULT, '默认', COMMENT))

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
            target = record.content
            resolver = dns.resolver.make_resolver_at('8.8.8.8')
            ret = resolver.resolve_name(target)
            if dns.rdatatype.A in ret:
                for i in ret[dns.rdatatype.A]:
                    record.type = RecordType.A
                    record.content = i.address
                    ans.append(copy.deepcopy(record))
            if dns.rdatatype.AAAA in ret:
                for i in ret[dns.rdatatype.AAAA]:
                    record.type = RecordType.AAAA
                    record.content = i.address
                    ans.append(copy.deepcopy(record))
        # add tailing dot for cname
        for record in ans:
            if record.type == RecordType.CNAME and not record.content.endswith('.'):
                record.content += '.'
        return ans

    def update_dns(self):
        pending_records = self.parse_records()
        old_records = self.get_records()
        # identical records
        to_delete = []
        for index, record in enumerate(pending_records):
            if record in old_records:
                index_now = old_records.index(record)
                if args.force:
                    logging.debug(f"Forcing updating '{record.name}'")
                    record.id = old_records[index_now].id
                else:
                    to_delete.append(index)
                del old_records[index_now]
        for index in reversed(to_delete):
            del pending_records[index]
        # updating records
        for index, record in enumerate(pending_records):
            for dp_record in old_records:
                if record.sims(dp_record):
                    logging.debug(
                        f"Updating '{record.name}' from '{dp_record.content}' ({type(dp_record.content)}) to '{record.content}' ({type(record.content)})")
                    record.id = dp_record.id
                    old_records.remove(dp_record)
                    break
        # staging
        adding_records = [i for i in pending_records if i.id == None]
        updating_records = [i for i in pending_records if i.id != None]
        deleting_records = [i for i in old_records]
        # print info
        logging.warning(
            f"Records to add: ({'none' if not adding_records else len(adding_records)})")
        for i in adding_records:
            print(i)
        logging.warning(
            f"Records to update: ({'none' if not updating_records else len(updating_records)})")
        for i in updating_records:
            print(i)
        logging.warning(
            f"Records to delete: ({'none' if not deleting_records else len(deleting_records)})")
        for i in deleting_records:
            print(i)
        # adding records
        op_counts = len(adding_records) + len(updating_records) + (1 if deleting_records else 0)
        if op_counts == 0:
            logging.warning("No changes to be made")
            return
        if args.dry_run:
            logging.warning("Dry run, no changes made")
            return
        print("Do you want to continue? [y/N]")
        if input().lower() != 'y':
            exit("Aborted")
        # validate
        for record in adding_records + updating_records + deleting_records:
            record.assert_valid()
        # do update
        with tqdm(total=op_counts) as pbar:
            for record in updating_records:
                request = models.ModifyRecordRequest()
                request.Domain = self.domain
                request.RecordId = record.id
                request.SubDomain = record.name
                request.RecordType = str(record.type)
                request.RecordLine = record.line
                request.Value = record.content
                request.TTL = record.ttl
                request.Remark = record.comment
                self.client.ModifyRecord(request)
                pbar.update(1)
            # do delete
            if len(deleting_records) > 0:
                request = models.DeleteRecordBatchRequest()
                request.RecordIdList = [i.id for i in deleting_records]
                self.client.DeleteRecordBatch(request)
                pbar.update(1)
            # do add
            # can't use CreateRecordBatch because it doesn't support remark
            for record in adding_records:
                request = models.CreateRecordRequest()
                request.Domain = self.domain
                request.SubDomain = record.name
                request.RecordType = str(record.type)
                request.RecordLine = record.line
                request.Value = record.content
                request.TTL = record.ttl
                request.Remark = record.comment
                self.client.CreateRecord(request)
                pbar.update(1)


if __name__ == "__main__":
    logging.warning(COMMENT)
    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)
    for domain, domain_config in config.items():
        client = DNSPodClient(domain, domain_config)
        client.update_dns()
