import requests
import keyring
from pprint import pprint

QUERY_DOMAIN = "zoom.us"
MIN_POSITIVE_SAMPLE_COUNT = 10
MAX_POSITIVE_SAMPLE_COUNT = 30


class VirusTotalClient:
    """
    a client wrapper for accessing the virus total api
    """
    vt_api_root = "https://www.virustotal.com/vtapi/v2"
    headers = {'Accept': 'application/json'}

    def __init__(self, api_key):
        self.api_key = api_key

    def base_query_params(self):
        return {'apikey': self.api_key}

    def get(self, url, query_params):
        url = f"{self.vt_api_root}{url}"
        params = self.base_query_params()
        params.update(query_params)

        response = requests.get(url, params=params, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            print(response)
            print("[!] throttled..")
            exit(1)
        return None
        
    def get_domain_report(self, domain):
        """
        return a virus total domain report for the provided domain
        """
        return self.get('/domain/report', query_params={
            'domain': domain
        })

    def get_file_report(self, sha256):
        """
        return file stuff from the virus total api for the provided whatever
        """
        return self.get('/file/report', query_params={
            'resource': sha256
        })


def get_domain_input():
    inp = input(f"Domain name [{QUERY_DOMAIN}]: ")
    trimmed = inp.strip()
    return trimmed or QUERY_DOMAIN


def get_referrer_file_hashes_from_report(report):
    samples_to_query = []
    detected_samples = report.get('detected_referrer_samples', [])

    for sample in detected_samples:
        if MIN_POSITIVE_SAMPLE_COUNT < sample.get("positives", 0) < MAX_POSITIVE_SAMPLE_COUNT:
            samples_to_query.append(sample['sha256'])
    return samples_to_query


def print_file_results(results):
    """
    process file query results and print formatted data to console
    """
    for file_hash, result in results.items():
        print(f"\n[-] {file_hash}")
        print(f"[-] Permalink: {result.get('permalink', '')}")

        for scan_name, scan in result.get('scans', {}).items():
            if not scan.get('detected', False):
                continue
            result = scan.get('result', '')
            updated = scan.get('update', '')
            print(f"\t\t[!] {scan_name:20}:\t\t({updated}) {result}")


def get_virustotal_api_key():
    """
    get the virus total api key from keystore, or from input
    if not found
    """
    key = keyring.get_password("virustotal", "apikey")
    if key is None:
        key = input("enter the virus total api key: ")
        keyring.set_password("virustotal", "apikey", key)
    return key


def main():
    api_key = get_virustotal_api_key()
    domain = get_domain_input()
    client = VirusTotalClient(api_key)
    client.get_domain_report(domain)


    print(f"[+] getting virus total domain report for {domain}")
    report = client.get_domain_report(domain)

    file_hashes = get_referrer_file_hashes_from_report(report)
    print(f"[+] retrieved {len(file_hashes)} files that meet criteria")

    file_results = {}
    for file_hash in file_hashes:
        print(f"[+] calling api for hash: {file_hash}")
        result = client.get_file_report(file_hash)

        if result is None:
            print(f"[!] file report for {file_hash} not found")
        else:
            print(f"[+] found {result.get('positives', 0)} positive results")
            file_results[file_hash] = result
    
    print_file_results(file_results)

    # write all api data to a file
    with open(f"{domain}.txt", "w") as f:
        f.write("======= DOMAIN REPORT\n\n")
        pprint(report, stream=f)
        f.write("\n\n======= FILE RESULTS")
        pprint(file_results, stream=f) 


if __name__ == "__main__":
    main()
