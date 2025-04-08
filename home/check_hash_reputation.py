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
def check_hash_reputation(hash):
    result = {}

    # AlienVault OTXv2 REPORT
    API_KEY_OTX = "5798cfa790846df1878999562232ae15ba23f80b7adc512ebb8394ecbbf1fd2e"
    try:
        BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
        url = 'indicators/file/'
        section = 'analysis'
        headers = {
            'accept': 'application/json',
            'X-OTX-API-KEY': API_KEY_OTX,
        }

        response = requests.get(BASE_URL + url + hash + '/' + section, headers=headers)
        ot_data = response.json()

        if ot_data:  # Check if response is not empty
                file_type = ot_data.get('analysis', {}).get('info', {}).get('results', {}).get('file_type')

                otx_result = {
                    "hash": hash,
                    "file_type": file_type,
                    "cuckoo_score": ot_data['analysis']['plugins']['cuckoo']['result']['info']['combined_score'],
                    "num_signatures": len(ot_data['analysis']['plugins']['cuckoo']['result']['signatures']),
                    "msdefender_results": ot_data['analysis']['plugins']['msdefender']['results'],
                    "avast_results": ot_data['analysis']['plugins']['avast']['results'],
                }
                result["alienvault_otxv2_report"] = otx_result
                
    except Exception as e:
        result["alienvault_otxv2_report"] = "Error: " + str(e)

        
    # VIRUSTOTAL REPORT
    vtapikey = "a18cb0212973d39d4b9064b81d7608f6c7ad05fe255b4e5967c3bed897be01c7"  # VirusTotal API Key
    try:
        response = requests.get("https://www.virustotal.com/api/v3/files/%s" % hash,
                                headers={'x-apikey': '%s' % vtapikey}).json()

        vt_result = {
            "hash_submitted": hash,
            "file_type": str(response['data']['attributes']['type_description']),
            "total_detection": str(response['data']['attributes']['last_analysis_stats']),
            "num_reports": int(response['data']['attributes']['last_analysis_stats']['malicious']) + int(response['data']['attributes']['last_analysis_stats']['suspicious']),
            "virustotal_reference": "https://www.virustotal.com/gui/file/" + hash
        }

        if 'signature_info' in response['data']['attributes']:
            vt_result["file_signature"] = str(response['data']['attributes']['signature_info'])
        else:
            vt_result["file_signature"] = "Data not available"

        if 'popular_threat_classification' in response['data']['attributes']:
            vt_result["threat_label"] = str(response['data']['attributes']['popular_threat_classification']['suggested_threat_label'])
        else:
            vt_result["threat_label"] = "Data not available"


        result["virustotal_report"] = vt_result
    except Exception as e:
        result["virustotal_report"] = "Error: " + str(e)

    return json.dumps(result)
