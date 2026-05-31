import ipaddress
import requests
import re
import os
import json
import csv
import time
import argparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# This script extracts valid IPv4 addresses from a given file.
def validate_ipv4(string):
    return string.count('.') == 3 and all(0 <= int(part) <= 255 for part in string.split('.'))

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def check_abuseipdb(ip):
    """
    Check an IP address against the AbuseIPDB API.

    Returns a dictionary with:
    - ip: the IP address checked
    - abuse_score: confidence score (0-100)
    - country: country code
    - isp: ISP name
    - total_reports: number of reports
    """
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        raise ValueError("ABUSEIPDB_API_KEY not found in environment")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if "data" in data:
            info = data["data"]
            return {
                "ip": ip,
                "abuse_score": info.get("abuseConfidenceScore"),
                "country": info.get("countryCode"),
                "isp": info.get("isp"),
                "total_reports": info.get("totalReports")
            }
        else:
            raise ValueError(f"Unexpected API response: {data}")
    except requests.RequestException as e:
        raise ValueError(f"API request failed: {e}")

def check_virustotal(ip):
    """
    Check an IP address against the VirusTotal API.

    Returns a dictionary with:
    - ip: the IP address checked
    - detections: number of vendors flagging the IP as malicious
    """
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        raise ValueError("VIRUSTOTAL_API_KEY not found in environment")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if "data" in data and "attributes" in data["data"]:
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            detections = stats.get("malicious", 0)
            result = {
                "ip": ip,
                "detections": detections
            }
            # Rate limiting: VT free tier allows 4 requests/minute
            time.sleep(15)
            return result
        else:
            raise ValueError(f"Unexpected API response: {data}")
    except requests.RequestException as e:
        raise ValueError(f"API request failed: {e}")

def get_verdict(abuse_score, vt_detections):
    """
    Determine verdict based on thresholds:
    - abuse_score > 25 OR vt_detections > 3: Malicious/IOC
    - Otherwise: Clean
    """
    if abuse_score > 25 or vt_detections > 3:
        return "Malicious (IOC)"
    else:
        return "Clean"

def generate_html_report(results, output_file='output/ioc_report.html'):
    """
    Generate an HTML report with IOC enrichment results.
    """
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>IOC Enrichment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .malicious { background-color: #ffcccc; font-weight: bold; }
        .clean { background-color: #ccffcc; }
        .suspicious { background-color: #ffffcc; font-weight: bold; }
    </style>
</head>
<body>
    <h1>IOC Enrichment Report</h1>
    <p>Generated: """ + str(__import__('datetime').datetime.now()) + """</p>
    <table>
        <tr>
            <th>IP Address</th>
            <th>AbuseIPDB Score</th>
            <th>VT Detections</th>
            <th>Country</th>
            <th>ISP</th>
            <th>Verdict</th>
        </tr>
"""

    for result in results:
        verdict_class = "malicious" if result['verdict'] == "Malicious (IOC)" else "clean"
        html_content += f"""        <tr class="{verdict_class}">
            <td>{result['ip']}</td>
            <td>{result['abuse_score']}</td>
            <td>{result['vt_detections']}</td>
            <td>{result['country']}</td>
            <td>{result['isp']}</td>
            <td>{result['verdict']}</td>
        </tr>
"""

    html_content += """    </table>
</body>
</html>"""

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(html_content)

    return output_file

def generate_csv_report(results, output_file='output/ioc_report.csv'):
    """
    Generate a CSV report with IOC enrichment results.
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    fieldnames = ['IP Address', 'AbuseIPDB Score', 'VT Detections', 'Country', 'ISP', 'Verdict']

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            writer.writerow({
                'IP Address': result['ip'],
                'AbuseIPDB Score': result['abuse_score'],
                'VT Detections': result['vt_detections'],
                'Country': result['country'],
                'ISP': result['isp'],
                'Verdict': result['verdict']
            })

    return output_file

def extract_ips(file_path):
    ips = []
    seen = set()
    ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # Read the file and extract valid IPv4 addresses from each line
    with open(file_path, 'r') as file:
        for line in file:
            for candidate in ipv4_pattern.findall(line):
                if validate_ipv4(candidate) and not is_private_ip(candidate) and candidate not in seen:
                    seen.add(candidate)
                    ips.append(candidate)

    # only return unique IPs in order of appearance
    return ips

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IOC Enrichment Tool - Enrich IPs with threat intelligence')
    parser.add_argument('--log-file', type=str, default='sample_logs/sample.log',
                        help='Path to log file to extract IPs from (default: sample_logs/sample.log)')
    parser.add_argument('--csv', action='store_true', help='Output results as CSV (in addition to HTML)')
    args = parser.parse_args()

    file_path = args.log_file
    extracted_ips = extract_ips(file_path)
    print(f"Extracted {len(extracted_ips)} public IPs from {file_path}")

    results = []
    for ip in extracted_ips:
        print(f"Checking {ip}...")
        try:
            abuse_info = check_abuseipdb(ip)
            vt_info = check_virustotal(ip)

            verdict = get_verdict(abuse_info['abuse_score'], vt_info['detections'])

            result = {
                'ip': ip,
                'abuse_score': abuse_info['abuse_score'],
                'vt_detections': vt_info['detections'],
                'country': abuse_info['country'],
                'isp': abuse_info['isp'],
                'verdict': verdict
            }
            results.append(result)
            print(f"  Abuse Score: {abuse_info['abuse_score']}, VT Detections: {vt_info['detections']}, Verdict: {verdict}")
        except Exception as e:
            print(f"  Error checking {ip}: {e}")

    # Generate HTML report
    html_report = generate_html_report(results)
    print(f"\nHTML report generated: {html_report}")

    # Generate CSV report if requested
    if args.csv:
        csv_report = generate_csv_report(results)
        print(f"CSV report generated: {csv_report}")
