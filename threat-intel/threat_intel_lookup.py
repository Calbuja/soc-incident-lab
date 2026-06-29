import requests
import json
from datetime import datetime

ABUSEIPDB_KEY = "15b1abaf6a5dc66c89b8ed8cb17773b7d47b1c6e10c91b7833a79b605fea22864dc9e0338520d074"
OTX_KEY = "c47d532e13709bcb32801b4afbc2e365417be4b1e2a24edba5e45d4d00bea197"

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        data = r.json()["data"]
        return {"abuse_score": data["abuseConfidenceScore"], "country": data["countryCode"], "isp": data["isp"], "total_reports": data["totalReports"]}
    except Exception as e:
        return {"error": str(e)}

def check_otx(ip):
    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        return {"pulse_count": data.get("pulse_info", {}).get("count", 0), "country": data.get("country_name", "Unknown")}
    except Exception as e:
        return {"error": str(e)}

def verdict(abuse_score, pulse_count):
    if abuse_score >= 70 or pulse_count >= 5:
        return "MALICIOUS - Escalate immediately"
    elif abuse_score >= 30 or pulse_count >= 1:
        return "SUSPICIOUS - Monitor and investigate"
    else:
        return "CLEAN - Low risk"

def enrich_ip(ip):
    print("\n" + "="*55)
    print("  IP: " + ip + "  |  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*55)
    abuse = check_abuseipdb(ip)
    otx = check_otx(ip)
    if "error" not in abuse:
        print("  [AbuseIPDB] Score   : " + str(abuse["abuse_score"]) + "/100")
        print("  [AbuseIPDB] Country : " + str(abuse["country"]) + " | ISP: " + str(abuse["isp"]))
        print("  [AbuseIPDB] Reports : " + str(abuse["total_reports"]))
    if "error" not in otx:
        print("  [OTX]       Pulses  : " + str(otx["pulse_count"]))
        print("  [OTX]       Country : " + otx["country"])
    score = abuse.get("abuse_score", 0)
    pulses = otx.get("pulse_count", 0)
    v = verdict(score, pulses)
    print("\n  VERDICT: " + v)
    print("="*55)
    return {"ip": ip, "abuseipdb": abuse, "otx": otx, "verdict": v}

if __name__ == "__main__":
    suspicious_ips = ["192.168.64.1", "8.8.8.8"]
    results = [enrich_ip(ip) for ip in suspicious_ips]
    with open("/home/csoc/Desktop/threat_intel_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n[*] Results saved to threat_intel_results.json")
