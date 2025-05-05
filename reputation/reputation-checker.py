import requests
import csv
import time

ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'

ip_list = ['192.0.2.123', '8.8.8.8']
domain_list = ['malicious-site.ru', 'example.com']

def check_ip_reputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': 30}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    return {
        'type': 'IP',
        'indicator': ip,
        'reputation_score': data['data']['abuseConfidenceScore'],
        'source': 'AbuseIPDB',
        'risk_level': 'High' if data['data']['abuseConfidenceScore'] > 50 else 'Medium' if data['data']['abuseConfidenceScore'] > 10 else 'Low'
    }

def check_domain_reputation(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)
    data = response.json()
    malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
    
    return {
        'type': 'Domain',
        'indicator': domain,
        'reputation_score': malicious_votes,
        'source': 'VirusTotal',
        'risk_level': 'High' if malicious_votes > 10 else 'Medium' if malicious_votes > 1 else 'Low'
    }

def write_to_csv(findings, filename='reputation_findings.csv'):
    keys = findings[0].keys()
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(findings)

if __name__ == "__main__":
    all_findings = []

    for ip in ip_list:
        try:
            finding = check_ip_reputation(ip)
            all_findings.append(finding)
        except Exception as e:
            print(f"Error checking IP {ip}: {e}")
        time.sleep(1)

    for domain in domain_list:
        try:
            finding = check_domain_reputation(domain)
            all_findings.append(finding)
        except Exception as e:
            print(f"Error checking domain {domain}: {e}")
        time.sleep(1)

    write_to_csv(all_findings)
    print("Reputation findings saved to reputation_findings.csv")
