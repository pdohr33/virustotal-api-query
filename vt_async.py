import asyncio
import aiohttp
from pprint import pprint

ZOOM_DOMAIN = "zoom.us"
MIN_POSITIVE_SAMPLE_COUNT = 10
MAX_POSITIVE_SAMPLE_COUNT = 30


class VirusTotalClient:
    """
    an asnyc client wrapper for accessing the virus total api
    """
    vt_api_root = "https://www.virustotal.com/vtapi/v2"
    headers = {'Accept': 'application/json'}

    def __init__(self, api_key):
        self.api_key = api_key

    def base_query_params(self):
        return {'apikey': self.api_key}

    async def get(self, url, query_params):
        url = f"{self.vt_api_root}{url}"
        params = self.base_query_params()
        params.update(query_params)

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=self.headers) as response:
                try:
                    return await response.json()
                except Exception as e:
                    print(e)
                    print(response)


    async def get_domain_report(self, domain):
        """
        return a virus total domain report for the provided domain
        """
        return await self.get('/domain/report', query_params={
            'domain': domain
        })

    async def get_file_report(self, sha256):
        """
        return file stuff from the virus total api for the provided whatever
        """
        print(f"[+] calling api for hash: {sha256}")
        return await self.get('/file/report', query_params={
            'resource': sha256
        })


def get_domain_input():
    inp = input(f"Domain name [{ZOOM_DOMAIN}]: ")
    trimmed = inp.strip()
    return trimmed or ZOOM_DOMAIN

def get_referrer_file_hashes_from_report(report):
    samples_to_query = []
    detected_samples = report.get('detected_referrer_samples', [])

    for sample in detected_samples:
        if MIN_POSITIVE_SAMPLE_COUNT < sample.get("positives", 0) < MAX_POSITIVE_SAMPLE_COUNT:
            samples_to_query.append(sample['sha256'])
    return samples_to_query

    # TODO: this does the same in a list comp
    # return [
    #     sample['sha256']
    #     for sample in report.get('detected_referral_samples', [])
    #     if MIN_POSITIVE_SAMPLE_COUNT < sample.get("positives", 0) < MAX_POSITIVE_SAMPLE_COUNT
    #     and sample.get('sha256') is not None
    # ]

async def main():
    # TODO: get api key from keystore
    api_key = "f3bcac22de74e670d707e26d09c46917cae8dbd89f813431e0a13120974deb79"

    domain = get_domain_input()

    client = VirusTotalClient(api_key)


    report = await client.get_domain_report(domain)
    file_hashes = get_referrer_file_hashes_from_report(report)
    print(f"[+] retrieved {len(file_hashes)} files that meet criteria")

    # concurrently call file api for each detected referrer sample
    # that meets the threshold
    # file_results = []
    # for file_hash in file_hashes:
    #     print(f"[+] calling api for hash: {file_hash}")
    #     result = await client.get_file_report(file_hash)
    #     file_results.append(result)

    file_api_calls = [
        client.get_file_report(file_hash)
        for file_hash in file_hashes
    ]

    file_api_results = asyncio.gather(*file_api_calls)
    # pprint(file_results)


if __name__ == "__main__":
    asyncio.run(main())