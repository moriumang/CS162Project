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
    result = {}

    # VIRUSTOTAL REPORT
    vtapikey = "a18cb0212973d39d4b9064b81d7608f6c7ad05fe255b4e5967c3bed897be01c7"
    try:
        baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': vtapikey, 'resource': url}
        response = requests.get(baseurl, params=params)
        vt_data = response.json()
        vt_result = {
            "url": str(vt_data['url']),
            "total_scan_attempts": str(vt_data['total']),
            "positives": str(vt_data['positives']),
            "permalink": str(vt_data['permalink']),
            "scans": vt_data['scans']
        }
        result["virustotal_report"] = vt_result
    except:
        result["virustotal_report"] = "URL not found or wrong input"

    # URL SCAN IO REPORT
    print("URL SCAN IO REPORT")
    print("------------------")
    urlscanapikey = "76d6b3e4-59a6-4c3a-97f8-f6e18f2ecf48"
    scan_type = 'public'
    headers = {'Content-Type': 'application/json', 'API-Key': urlscanapikey}
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers,
                                 data='{"url": "%s", "%s": "on"}' % (url, scan_type)).json()
        result["urlscan_io_report_message"] = response['message']
        result["urlscan_io_report_visibility"] = response['visibility']
        result["urlscan_io_report_uuid"] = response['uuid']
        if 'successful' in response['message']:
            result["urlscan_io_report_scanning_status"] = "Scanning %s." % url
            result["urlscan_io_report_waiting_message"] = "We're waiting for this website to finish loading. This might take a minute."
            time.sleep(50)
            final_response = requests.get('https://urlscan.io/api/v1/result/%s/' % response['uuid']).json()
            result["urlscan_io_report_url_scanned"] = str(final_response['task']['url'])
            result["urlscan_io_report_overall_score"] = str(final_response['verdicts']['overall']['score'])
            result["urlscan_io_report_malicious"] = str(final_response['verdicts']['overall']['malicious'])
            result["urlscan_io_report_screenshot_url"] = str(final_response['task']['screenshotURL'])
            result["urlscan_io_report_urlscan_score"] = str(final_response['verdicts']['urlscan']['score'])
            if final_response['verdicts']['urlscan']['categories']:
                result["urlscan_io_report_categories"] = [str(line) for line in final_response['verdicts']['urlscan']['categories']]
            result["urlscan_io_report_report_reference"] = str(final_response['task']['reportURL'])
    except:
        result["urlscan_io_report_error"] = "An Error has occurred, the domain could not be resolved and scanned by URL SCAN due to restrictions"

    return json.dumps(result)
