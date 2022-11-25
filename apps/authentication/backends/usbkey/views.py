import base64
import json
import time
import uuid

import requests
from django.views import View
from django.http import HttpResponse

from common.utils import get_logger
from jumpserver.const import CONFIG

logger = get_logger(__name__)


class UsbKeyChallenge(View):
    @staticmethod
    def getSsdp():
        params = {
            "Api_ID": CONFIG.UKEY_API_ID,
            "Api_Version": CONFIG.UKEY_API_VERSION,
            "App_Sub_ID": CONFIG.UKEY_APP_SUB_ID,
            "App_Token": CONFIG.UKEY_APP_TOKEN,
            "ENV": CONFIG.UKEY_ENV,
            "Partner_ID": CONFIG.UKEY_PARTNER_ID,
            "Sign": CONFIG.UKEY_SIGN,
            "Sys_ID": CONFIG.UKEY_SYS_ID,
            "Time_Stamp": str(int(time.time() * 1000)),
            "User_Token": CONFIG.UKEY_USER_TOKEN,
            "appKey": "a4f33f7d7e2b43128c28760cee4ecee6"
        }

        keys = ["Api_ID", "Api_Version", "App_Sub_ID", "App_Token", "ENV", "Partner_ID", "Sign", "Sys_ID", "Time_Stamp",
                "User_Token"]
        ss = []
        for k in keys:
            ss.append(k + "=" + params.get(k))

        ssdp = "&".join(ss)
        logger.info('unbase64_ssdp: {}'.format(ssdp))
        return base64.b64encode(ssdp.encode('utf-8')).decode('utf-8')

    def getChallenge(self):
        ssdp = self.getSsdp()
        url = CONFIG.UKEY_ECSB_DOMAIN + '/ecsb/gw/sys/rf?ssdp=' + ssdp
        rand = "".join(str(uuid.uuid4()).split("-"))
        params = {
            "header": {
            },
            "body": {},
            "param": {
                "interfacePath": "/sign_api/getCodeData",
                "urlParam": f"rand={rand}&alg=2"
            },
            "httpMethod": "GET"
        }
        header = {
            "clientId": CONFIG.UKEY_CLIENT_ID,
            "timestamp": str(int(time.time() * 1000))
        }
        logger.info('getChallenge params: {}'.format(params))
        response = requests.post(url, json=params, headers=header)
        data = response.json()
        b64data = data.get("data")
        ret = json.loads(base64.b64decode(b64data.encode('utf-8')))
        rand = ret.get("rand")
        b64Challenge = base64.b64encode(rand.encode('utf-8')).decode('utf-8')
        return {
            'b64Challenge': b64Challenge,
            'rand': rand,
            'url': url
        }

    def get(self, request):
        return HttpResponse(json.dumps(self.getChallenge()))
