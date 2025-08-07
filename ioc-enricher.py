import requests
import json

IOC_data = {
    "ip_address": "", 
    "country": "",    # from absueIP
    "abuseIP_report": list(),
    "alienvault_passive_DNS": list(),
    "alienvault_malware": list(),
    "alienvault_url_list": list()
}

def abuseIP_cate_converter(categories):
    return_list = list()
    CATEGORY_MAP = {
        14: "Port Scan", 18: "Brute-Force", 21: "Web App Attack",
        22: "SSH", 16: "SQL Injection", 20: "Exploited Host",
        19: "Bad Web Bot", 10: "Web Spam", 11: "Email Spam",
        13: "VPN IP", 15: "Hacking", 23: "IoT Targeted",
        1: "DNS Compromise", 2: "DNS Poisoning", 4: "DDoS Attack",
        5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing",
        8: "Fraud VoIP", 9: "Open Proxy", 12: "Blog Spam",
        17: "Spoofing", 3: "Fraud Orders"
    }
    if len(categories) > 0:
        for item in categories:
            return_list.append(CATEGORY_MAP[item])
        return return_list
    else:
        return return_list        

def abuseIP(ip_address):
    abuse_key = '34f82a6f1c84d85b3eced18891d293eadcc40421adb26613ed61ae9e54564e87a8f419c64c96c6c3'
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuse_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    decodedResponse = json.loads(response.text)
    country = decodedResponse['data']['countryName']
    IOC_data['country'] = country
    
    reports = decodedResponse['data']['reports']
    reports_list = list()
    if len(reports) > 0:
        for report in reports:
            temp_dict = {
                "reportedAt": report['reportedAt'],
                "comment": report['comment'],
                "categories": abuseIP_cate_converter(report['categories'])
            }
            reports_list.append(temp_dict)
        IOC_data['abuseIP_report'] = reports_list
    else:
        IOC_data['abuseIP_report'] = reports_list


def alienvault(ip_address):
    alienvault_passive_dns = list()
    passive_dns_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/103.157.97.15/passive_dns"    
    passive_dns_response = requests.get(url=passive_dns_url)
    decodedResponse = json.loads(passive_dns_response.text)




































def main():
    ip_address = '47.251.93.227'
    IOC_data['ip_address'] = ip_address
    # abuseIP(ip_address)
    alienvault(ip_address=ip_address)
    print(IOC_data)

if __name__ == "__main__":
    main()