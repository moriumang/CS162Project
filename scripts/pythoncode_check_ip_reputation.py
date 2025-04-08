import base64
import json
from ipwhois import IPWhois
import requests
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

def check_ip_reputation(ip):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = "a18cb0212973d39d4b9064b81d7608f6c7ad05fe255b4e5967c3bed897be01c7"   # Replace "your_virustotal_api_key" with your actual API key
    try:
        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
                                headers={'x-apikey': vtapikey})
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        reference = "https://www.virustotal.com/gui/ip-address/" + ip
        print("IP Address                  :", ip)
        if 'as_owner' in resp['data']['attributes']:
            print("IP Address Owner            :", str(resp['data']['attributes']['as_owner']))
        print("Number of scan attempted    :", str(resp['data']['attributes']['last_analysis_stats']))
        print("Reputation                  :", str(resp['data']['attributes']['reputation']))
        print("\nNumber of Reportings      :", (
                    int(resp['data']['attributes']['last_analysis_stats']['malicious']) + int(
                resp['data']['attributes']['last_analysis_stats']['suspicious'])))
        print("Virustotal report reference :", reference)
    except:
        print("IP not found or wrong input")

    print("\n")
    print("-----------------")
    print("ABUSEIPDB REPORT")
    print("-----------------")

    ABIPDB_KEY = "d97ca07416e1bf9857b0ca3182ea58a3b036e42dc6bdeaab465f874aaedda5a39989bb0457668bb7"  # Replace "your_abuseipdb_api_key" with your actual API key
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
    reference = "https://www.abuseipdb.com/check/" + ip

    try:
        response = requests.request(method='GET', url=ABIPDB_URL, headers=headers, params=querystring)
        result = response.json()
        print("\nIP Address      :" + str(result['data']['ipAddress']))
        print("Number of Reports :" + str(result['data']['totalReports']))
        print("Abuse Score       :" + str(result['data']['abuseConfidenceScore']) + "%")
        print("Last Reported on  :" + str(result['data']['lastReportedAt']))
        print("Report Reference  :" + reference)
    except:
        print("IP not found")

    print("\n")
    print("---------------------")
    print("AlienVault OTX REPORT")
    print("---------------------")

    OTX_KEY = "5798cfa790846df1878999562232ae15ba23f80b7adc512ebb8394ecbbf1fd2e"  # Replace "your_otx_api_key" with your actual API key
    BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
    url = 'indicators/IPv4/'
    headers = {
        'accept': 'application/json',
        'X-OTX-API-KEY': OTX_KEY,
    }

    reference = "https://otx.alienvault.com/indicator/ip/" + ip
    response = requests.get(BASE_URL + url + ip + '/', headers=headers)
    resp = response.json()
    print("IP Address      :", resp['indicator'])
    print("IP Address Type :", resp['type'])
    print("IP Owner/ASN    :", resp['asn'])
    print("City            :", resp['city'])
    print("Country         :", resp['country_name'])
    tags = dict()
    for i in range(0, resp['pulse_info']['count']):
        for l in resp['pulse_info']['pulses'][i]['tags']:
            tags[l] = tags.get(l, 0) + 1
    print("Tags            :", tags)
    print("Reference       :", reference)

    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        addr = str(res['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n")
        print("------------")
        print("WHOIS RECORD")
        print("------------")
        print("CIDR    :" + str(res['nets'][0]['cidr']))
        print("Name    :" + str(res['nets'][0]['name']))
        print("Range   :" + str(res['nets'][0]['range']))
        print("Descr   :" + str(res['nets'][0]['description']))
        print("Country :" + str(res['nets'][0]['country']))
        print("Address :" + addr)
        print("Created :" + str(res['nets'][0]['created']))
        print("Updated :" + str(res['nets'][0]['updated']))
    except:
        print("Invalid or Private IP Address")

    print("\n\n")
    ret = int(input("Enter 1 to return to menu:\n"))
    if ret == 1:
        return
    else:
        print("Wrong input, returning anyways")
        return
