import logging
from tqdm import tqdm
from tencentcloud.common import credential
from tencentcloud.dnspod.v20210323 import dnspod_client, models
from dnsutils import DNSRecord, RecordType


class DNSPodClient:
    def __init__(self, domain: str, auth: dict, prefix: str):
        self.domain = domain
        self.prefix = prefix
        cred = credential.Credential(auth['secret_id'], auth['secret_key'])
        self.client = dnspod_client.DnspodClient(cred, "")
        logging.debug("DNSPod client initialized")

    def get_records(self):
        logging.debug(f"Getting records for domain {self.domain}")
        request = models.DescribeRecordListRequest()
        request.Domain = self.domain
        response = self.client.DescribeRecordList(request)
        ans = []
        for record in response.RecordList:
            if record.Remark and self.prefix in record.Remark:
                type = RecordType(record.Type)
                ans.append(DNSRecord(
                    record.Name, type, record.Value, record.TTL, None if record.Line == '默认' else record.Line, record.Remark, record.RecordId))
        for i in ans:
            i.assert_valid()
        logging.info(f"Got {len(ans)} records in total {len(response.RecordList)} records from DNSPod")
        return ans

    def update_records(self, adding, updating, deleting):
        op_counts = len(adding) + len(updating) + (1 if deleting else 0)
        with tqdm(total=op_counts) as pbar:
            # do update
            for record in updating:
                request = models.ModifyRecordRequest()
                request.Domain = self.domain
                request.RecordId = record.id
                request.SubDomain = record.name
                request.RecordType = str(record.type)
                request.RecordLine = '默认' if record.line is None else record.line
                request.Value = record.content
                request.TTL = record.ttl
                request.Remark = record.comment
                self.client.ModifyRecord(request)
                pbar.update(1)
            # do delete
            if len(deleting) > 0:
                request = models.DeleteRecordBatchRequest()
                request.RecordIdList = [i.id for i in deleting]
                self.client.DeleteRecordBatch(request)
                pbar.update(1)
            # do add
            # can't use CreateRecordBatch because it doesn't support remark
            for record in adding:
                request = models.CreateRecordRequest()
                request.Domain = self.domain
                request.SubDomain = record.name
                request.RecordType = str(record.type)
                request.RecordLine = '默认' if record.line is None else record.line
                request.Value = record.content
                request.TTL = record.ttl
                request.Remark = record.comment
                self.client.CreateRecord(request)
                pbar.update(1)
