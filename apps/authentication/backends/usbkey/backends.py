# -*- coding: utf-8 -*-
#
import base64
import json
import time

import requests
from django.utils.translation import ugettext as _

from common.utils import get_object_or_none, get_logger
from jumpserver.const import CONFIG
from users.models import User
from ..base import JMSBaseAuthBackend, UserModel

__all__ = ['UsbKeyBackend']

from ... import errors

from ...errors import AuthFailedError

logger = get_logger(__name__)


class UsbKeyBackend(JMSBaseAuthBackend):
    @staticmethod
    def is_enabled():
        return True

    def authenticate(self, request, username='', password='', *args, **kwargs):
        ecsburl = request.POST.get('ecsburl', '')
        rand = request.POST.get('rand')
        sign = request.POST.get('sign')

        if len(ecsburl) > 0:
            params = {
                "ver": 2,
                "alg": "RAND",
                "rand": rand,
                "sid": username + '@PIM',
                "resp": sign,
                "keytype": "SM9_FULL"
            }

            logger.info('request ecsb params: {}'.format(params))

            paramstr = base64.b64encode(json.dumps(params).encode('utf-8')).decode('utf-8')

            body = {
                "header": {
                    "Content-Type": "application/json"
                },
                "body": paramstr,
                "param": {
                    "interfacePath": "/sign_api/verify"
                },
                "httpMethod": "POST"
            }
            header = {
                "clientId": CONFIG.UKEY_CLIENT_ID,
                "timestamp": str(int(time.time() * 1000))
            }
            logger.info('request ecsb body: {}, header: {}'.format(params, header))
            response = requests.post(ecsburl, json=body, headers=header)
            js = response.json()
            data = json.loads(base64.b64decode(js.get("data").encode('utf-8')))
            logger.info('request ecsb end: {}'.format(data))
            status = data.get('status')
            if status != 1:
                errmsg = 'code: {}, msg: {}'.format(status, data.get('msg'))
                if status in [-93, -4520, -4501]:
                    errmsg = 'code: {}, msg: {}'.format(status, errors.usbkey_pin_error_msg)
                elif status in [-4512, -4599, -4600]:
                    errmsg = 'code: {}, msg: {}'.format(status, errors.usbkey_locked_msg)
                logger.error(errmsg)
                raise AuthFailedError(username=username, error=errors.reason_ukey_sign_fail, msg=errmsg)

            # 成功登录
            return get_object_or_none(User, username=username)

    def get_user(self, user_id):
        try:
            user = UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None

