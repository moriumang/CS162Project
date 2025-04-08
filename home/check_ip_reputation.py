import json
import requests
from ipwhois import IPWhois

def check_ip_reputation(ip):
    result = {}

    # VIRUSTOTAL REPORT
    vtapikey = "a18cb0212973d39d4b9064b81d7608f6c7ad05fe255b4e5967c3bed897be01c7"
    try:
        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
                                headers={'x-apikey': vtapikey})
        vt_data = response.json()
        vt_result = {
            "ip_address": ip,
            "owner": vt_data['data']['attributes'].get('as_owner', ''),
            "scan_attempted": vt_data['data']['attributes']['last_analysis_stats'],
            "reputation": vt_data['data']['attributes']['reputation'],
            "num_reports": int(vt_data['data']['attributes']['last_analysis_stats']['malicious']) + \
                           int(vt_data['data']['attributes']['last_analysis_stats']['suspicious']),
            "reference": "https://www.virustotal.com/gui/ip-address/" + ip
        }
        result["virustotal_report"] = vt_result
    except:
        result["virustotal_report"] = "IP not found or wrong input"

    # ABUSEIPDB REPORT
    ABIPDB_KEY = "d97ca07416e1bf9857b0ca3182ea58a3b036e42dc6bdeaab465f874aaedda5a39989bb0457668bb7"
    ABIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
    days = '180'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': days
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABIPDB_KEY
    }
    reference_abuse = "https://www.abuseipdb.com/check/" + ip
    try:
        response = requests.request(method='GET', url=ABIPDB_URL, headers=headers, params=querystring)
        abuse_data = response.json()
        abuse_result = {
            "ip_address": abuse_data['data']['ipAddress'],
            "num_reports": abuse_data['data']['totalReports'],
            "abuse_score": abuse_data['data']['abuseConfidenceScore'],
            "last_reported": abuse_data['data']['lastReportedAt'],
            "reference": reference_abuse
        }
        result["abuseipdb_report"] = abuse_result
    except:
        result["abuseipdb_report"] = "IP not found"

    # AlienVault OTX REPORT
    OTX_KEY = "5798cfa790846df1878999562232ae15ba23f80b7adc512ebb8394ecbbf1fd2e"
    BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
    url = 'indicators/IPv4/'
    headers = {
        'accept': 'application/json',
        'X-OTX-API-KEY': OTX_KEY,
    }
    reference_otx = "https://otx.alienvault.com/indicator/ip/" + ip
    response = requests.get(BASE_URL + url + ip + '/', headers=headers)
    ot_data = response.json()
    ot_result = {
    "ip_address": ot_data['indicator'],
    "ip_type": ot_data['type'],
    "ip_owner": ot_data['asn'],
    "city": ot_data['city'],
    "country": ot_data['country_name'],
    "reference": reference_otx,
    "tags": ot_data['pulse_info']['pulses'][0]['tags'][0] if ot_data['pulse_info']['pulses'] and ot_data['pulse_info']['pulses'][0]['tags'] else None,
}
    result["alienvault_otx_report"] = ot_result

    # WHOIS RECORD
    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        whois_result = {
            "cidr": str(res['nets'][0]['cidr']),
            "name": str(res['nets'][0]['name']),
            "range": str(res['nets'][0]['range']),
            "description": str(res['nets'][0]['description']),
            "country": str(res['nets'][0]['country']),
            "address": str(res['nets'][0]['address']),
            "created": str(res['nets'][0]['created']),
            "updated": str(res['nets'][0]['updated'])
        }
        result["whois_record"] = whois_result
    except:
        result["whois_record"] = "Invalid or Private IP Address"

    return json.dumps(result)
