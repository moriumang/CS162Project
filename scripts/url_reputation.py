import base64
from ipwhois import IPWhois
import json
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import re
import requests
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


def check_url_reputation(url):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = "a18cb0212973d39d4b9064b81d7608f6c7ad05fe255b4e5967c3bed897be01c7"
    try:
        baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': vtapikey, 'resource': url}
        response = requests.get(baseurl, params=params)
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)

        # print(resp) # VIRUSTOTAL IS NOT A GREAT RESOURCE FOR URL REPUTATION however v2 works fine
        print("URL Submitted               :", str(resp['url']))
        print("Number of scan attempted    :", str(resp['total']))
        print("Number of Reportings        :", str(resp['positives']))
        print("Virustotal report reference :", str(resp['permalink']))

        res = list(resp['scans'].values())
        tags = dict()
        for i in range(0, len(res)):
            tags[str(res[i]['result'])] = tags.get(str(res[i]['result']), 0) + 1
        print("Tags                        :", tags)
    except:
        print("URL not found or wrong input")

    print("\n")
    print("-----------------------")
    print("AlienVault OTXv2 REPORT")
    print("-----------------------")

    try:
        otx = OTXv2(config.key_dictionary['AlienVault OTX API Key'])
        final_domain = urlparse(url).netloc
        results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, final_domain)
        print("URL                         :", results['general']['indicator'])
        print("Type                        :", results['general']['type_title'])
        print("Number of Detections/Pulses :", results['general']['pulse_info']['count'])
        print("Possible Malware Detection  :", len(results['malware']['data']))
        print("URL Lists Counts            :", len(results['url_list']['url_list']))
        tags = list()
        for i in range(0, len(results['general']['validation'])):
            tags.append(results['general']['validation'][i]['name'])
        length_of_validation = len(tuple(tags))
        if length_of_validation > 0:
            print("Validation tags             :", tuple(tags))
        else:
            print("Validtion tags              : Suspicious as the URL/Domain is not listed on Major SEs")
    except:
        print("URL Not Found on AlientVault OTX searches")

    print("\n")
    print("----------------")
    print("Phishtank Report")
    print("----------------")

    try:
        headers = {
            'format': 'json'
        }

        BASE_URL = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = url.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        BASE_URL += base64_new_check
        response = requests.request("POST", url=BASE_URL, headers=headers)
        root = ET.fromstring(response.text)
        print("Submitted URL     :", root[1][0][0].text)
        print("Found in Database :", root[1][0][1].text)
        print("Phish ID          :", root[1][0][2].text)
        print("Reference         :", root[1][0][3].text)
        print("Verified          :", root[1][0][4].text)
        if root[1][0][4].text == 'true':
            print("Verification Date :", root[1][0][5].text)
            print("is still Valid    :", root[1][0][6].text)
    except:
        print("The URL is not listed for Phishing in Phishtank's DB")

    print("\n")
    print("------------------")
    print("URL SCAN IO REPORT")
    print("------------------")

    urlscanapikey = config.key_dictionary['URLScan IO API Key']
    scan_type = 'private'
    type = str(input('''Do you want to run a public scan?[y/N]
    A public scan result will be available in URL SCAN IO DB and searchable on open internet.
    Default is private.'''))

    if type == 'y':
        scan_type = 'public'

    headers = {'Content-Type': 'application/json', 'API-Key': urlscanapikey, }
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers,
                                 data='{"url": "%s", "%s": "on"}' % (url, scan_type)).json()
        print(response['message'])
        print("Visibility :", response['visibility'])
        print("Unique ID  :", response['uuid'])

        if 'successful' in response['message']:
            print("Scanning %s." % url)
            print("\n")
            print(
                "We're waiting for this website to finish loading. This might take a minute.\nYou will automatically be redirected to the result, you do not have to rerun any command!")
            time.sleep(50)
            final_response = requests.get('https://urlscan.io/api/v1/result/%s/' % response['uuid']).json()
            print("\n")
            print("------------------")
            print("URL SCAN IO REPORT")
            print("------------------")
            print("\n")
            print("URL Scanned       :", str(final_response['task']['url']))
            print("Overall Score     :", str(final_response['verdicts']['overall']['score']))
            print("Malicious         :", str(final_response['verdicts']['overall']['malicious']))
            print("Screenshot of URL :", str(final_response['task']['screenshotURL']))
            print("URLSCAN Score     :", str(final_response['verdicts']['urlscan']['score']))
            if final_response['verdicts']['urlscan']['categories']:
                print("Categories: ")
                for line in final_response['verdicts']['urlscan']['categories']:
                    print("\t" + str(line))
            print("URLSCAN Report Reference :", str(final_response['task']['reportURL']))
    except:
        print("An Error has occured, the domain could not be resolved and scanned by URL SCAN due to restrictions")

    print("\n\n")
    ret = int(input("Enter 1 to return to menu:\n"))
    if ret == 1:
        return
    else:
        print("Wrong input, returing anyways")
        return

