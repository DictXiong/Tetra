import cloudflare
from tqdm import tqdm
from ..dnsutils import DNSRecord, RecordType


class CloudflareClient:
    def __init__(self, domain: str, auth: dict, prefix: str, logger):
        self.domain = domain
        self.prefix = prefix
        self.logger = logger
        if "token_file" in auth:
            with open(auth["token_file"], "r", encoding="utf-8") as f:
                token = f.read().strip()
        else:
            token = auth["token"]
        self.cf = cloudflare.Cloudflare(api_token=token)
        zones = self.cf.zones.list(name=domain)
        zone = None
        for i in zones:
            if zone is not None:
                self.logger.fatal("api call returned >1 zones")
                exit(1)
            zone = i
        if zone is None:
            self.logger.fatal("zone %s not found", domain)
        self.zone_id = zone.id
        self.logger.debug("cloudflare client initialized")

    def get_records(self):
        self.logger.debug("getting records for domain %s", self.domain)
        dns_records = self.cf.dns.records.list(zone_id=self.zone_id)
        len_dns_records = 0
        cf_records = []
        for record in dns_records:
            len_dns_records += 1
            if record.comment and self.prefix in record.comment:
                record_type = RecordType(record.type)
                if record_type == RecordType.CNAME and not record.content.endswith("."):
                    record.content += "."
                name = record.name.replace(f".{self.domain}", "")
                if name == self.domain:
                    name = "@"
                cf_records.append(
                    DNSRecord(
                        name,
                        record_type,
                        record.content,
                        record.ttl,
                        None,
                        record.comment,
                        record.id,
                    )
                )
        for i in cf_records:
            i.assert_valid()
        self.logger.info(
            "Got %i records in total %i records from Cloudflare",
            len(cf_records),
            len_dns_records,
        )
        return cf_records

    def update_records(self, adding, updating, deleting):
        op_counts = len(adding) + len(updating) + len(deleting)
        with tqdm(total=op_counts) as pbar:
            for record in updating:
                assert record.line is None, "Cloudflare doesn't support line"
                self.cf.dns.records.update(
                    zone_id=self.zone_id,
                    dns_record_id=record.id,
                    name=record.name,
                    type=str(record.type),
                    content=record.content,
                    ttl=record.ttl,
                    comment=record.comment,
                    proxied=False,
                )
                pbar.update(1)
            for record in deleting:
                self.cf.dns.records.delete(
                    zone_id=self.zone_id, dns_record_id=record.id
                )
                pbar.update(1)
            for record in adding:
                assert record.line is None, "Cloudflare doesn't support line"
                self.cf.dns.records.create(
                    zone_id=self.zone_id,
                    name=record.name,
                    type=str(record.type),
                    content=record.content,
                    ttl=record.ttl,
                    comment=record.comment,
                    proxied=False,
                )
                pbar.update(1)
