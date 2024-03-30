import CloudFlare
import logging
from tqdm import tqdm
from dnsutils import DNSRecord, RecordType

class CloudflareClient:
    def __init__(self, domain: str, auth: dict, prefix: str):
        self.domain = domain
        self.prefix = prefix
        self.cf = CloudFlare.CloudFlare(token=auth['token'])
        zones = self.cf.zones.get(params={'name': domain})
        if len(zones) != 1:
            raise ValueError(f"Zone {domain} not found")
        self.zone_id = zones[0]['id']
        logging.debug("Cloudflare client initialized")
    
    def get_records(self):
        logging.debug(f"Getting records for domain {self.domain}")
        dns_records = self.cf.zones.dns_records.get(self.zone_id)
        cf_records = []
        for record in dns_records:
            if record['comment'] and self.prefix in record['comment']:
                type = RecordType(record['type'])
                if type == RecordType.CNAME and not record['content'].endswith('.'):
                    record['content'] += '.'
                name = record['name'].replace(f'.{self.domain}', '')
                if name == self.domain:
                    name = '@'
                cf_records.append(DNSRecord(
                    name, type, record['content'], record['ttl'], None, record['comment'], record['id']))
        for i in cf_records:
            i.assert_valid()
        return cf_records

    def update_records(self, adding, updating, deleting):
        op_counts = len(adding) + len(updating) + len(deleting)
        with tqdm(total=op_counts) as pbar:
            for record in updating:
                assert record.line == None, "Cloudflare doesn't support line"
                self.cf.zones.dns_records.put(self.zone_id, record.id, data={'name': record.name, 'type': str(record.type), 'content': record.content, 'ttl': record.ttl, 'comment': record.comment, 'proxied': False})
                pbar.update(1)
            for record in deleting:
                self.cf.zones.dns_records.delete(self.zone_id, record.id)
                pbar.update(1)
            for record in adding:
                assert record.line == None, "Cloudflare doesn't support line"
                self.cf.zones.dns_records.post(self.zone_id, data={'name': record.name, 'type': str(record.type), 'content': record.content, 'ttl': record.ttl, 'comment': record.comment, 'proxied': False})
                pbar.update(1)
