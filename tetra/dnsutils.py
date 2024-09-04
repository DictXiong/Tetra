import ipaddress
import enum
import copy
import logging
import dns.resolver
import dns.rdatatype


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
        if self.type == RecordType.AAAA:
            self.content = str(ipaddress.ip_address(content))
        else:
            self.content = content
        self.ttl = ttl
        self.line = line
        self.comment = comment
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

    def summary(self):
        return f'{self.name} in {self.type} {self.content}' + (f' [{self.line}]' if self.line else '')

    def __str__(self):
        self.assert_valid()
        return f'{self.name:23} {self.ttl:5}  IN  {self.type:5} {self.content:39}' + (f' [{self.line}]' if self.line else '') + (f' ; {self.comment}' if self.comment else '')

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, DNSRecord):
            raise ValueError(f"type {type(self)} could not be compared with {type(__value)}")
        return self.name == __value.name and self.type == __value.type and self.content == __value.content and self.ttl == __value.ttl and self.line == __value.line

    def sims(self, __value: object) -> bool:
        if not isinstance(__value, DNSRecord):
            raise ValueError(f"type {type(self)} could not be compared with {type(__value)}")
        return self.name == __value.name and self.type == __value.type


def cross_compare(old_records: list[DNSRecord], pending_records: list[DNSRecord], force: bool=False):
    assert isinstance(old_records, list) and isinstance(pending_records, list)
    old_records = old_records[:]
    pending_records = pending_records[:]
    # identical records
    to_delete = []
    for index, record in enumerate(pending_records):
        if record in old_records:
            index_now = old_records.index(record)
            if force:
                logging.debug(f"Forcing updating '{record.name}'")
                record.id = old_records[index_now].id
            else:
                to_delete.append(index)
            del old_records[index_now]
    for index in reversed(to_delete):
        del pending_records[index]
    # updating records
    for index, record in enumerate(pending_records):
        for i in old_records:
            if record.sims(i):
                logging.debug(
                    f"Updating '{record.name}' from '{i.content}' ({type(i.content)}) to '{record.content}' ({type(record.content)})")
                logging.debug(f"diff: content={record.content==i.content} ttl={record.ttl==i.ttl} line={record.line==i.line}")
                record.id = i.id
                old_records.remove(i)
                break
    # staging
    adding_records = [i for i in pending_records if i.id is None]
    updating_records = [i for i in pending_records if i.id is not None]
    deleting_records = [i for i in old_records]
    return adding_records,updating_records,deleting_records

def resolve_name_to_template(domain: str, template: DNSRecord):
    ans = []
    resolver = dns.resolver.Resolver()
    ret = resolver.resolve_name(domain)
    if dns.rdatatype.A in ret:
        for i in ret[dns.rdatatype.A]:
            template.type = RecordType.A
            template.content = i.address
            ans.append(copy.deepcopy(template))
    if dns.rdatatype.AAAA in ret:
        for i in ret[dns.rdatatype.AAAA]:
            template.type = RecordType.AAAA
            template.content = i.address
            ans.append(copy.deepcopy(template))
    return ans

def assert_cname_unique(records: list[DNSRecord]):
    for i in records:
        if i.type == RecordType.CNAME:
            for j in records:
                if i.name == j.name and i.line == j.line and i != j:
                    raise ValueError(f"Duplicate CNAME record {i.summary()} {j.summary()}")

def check_name_exist(domain: str):
    resolver = dns.resolver.Resolver()
    try: resolver.resolve_name(domain)
    except dns.resolver.NXDOMAIN:
        return False
    except Exception as e:
        logging.warning(f"an error occured when quering {domain}")
    return True
