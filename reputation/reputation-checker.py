import json
import re
import requests
import csv

VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'

def load_trivy_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def extract_indicators(trivy_data):
    urls = set()
    if isinstance(trivy_data, list):  # sometimes Trivy JSON is a list of targets
        items = trivy_data
    else:
        items = [trivy_data]

    for item in items:
        for result in item.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                for ref in vuln.get('References', []):
                    urls.add(ref)
            for misconf in result.get('Misconfigurations', []):
                for ref in misconf.get('References', []):
                    urls.add(ref)
    return extract_domains_and_ips(urls)

def extract_domains_and_ips(urls):
    indicators = set()
    domain_pattern = re.compile(r'https?://([^/]+)')
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    for url in urls:
        # Match IPs directly
        ips = ip_pattern.findall(url)
        indicators.update(ips)
        # Match domains
        match = domain_pattern.search(url)
        if match:
            indicators.add(match.group(1))
    return list(indicators)

def check_domain_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None

    data = response.json()
    stats = data['data']['attributes']['last_analysis_stats']
    return {
        'indicator': domain,
        'malicious': stats['malicious'],
        'suspicious': stats['suspicious'],
        'harmless': stats['harmless'],
        'undetected': stats['undetected'],
        'risk_level': 'High' if stats['malicious'] > 10 else 'Medium' if stats['malicious'] > 1 else 'Low'
    }

def write_results_to_csv(results, filename='reputation_enriched.csv'):
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    trivy_file = 'trivy_results.json'
    trivy_data = load_trivy_json(trivy_file)
    indicators = extract_indicators(trivy_data)
    print(f"Found {len(indicators)} unique indicators.")

    enriched_results = []
    for ind in indicators:
        print(f"Checking: {ind}")
        result = check_domain_virustotal(ind)
        if result:
            enriched_results.append(result)

    if enriched_results:
        write_results_to_csv(enriched_results)
        print("Enriched report saved as reputation_enriched.csv")
    else:
        print("No valid indicators found or VT query failed.")
