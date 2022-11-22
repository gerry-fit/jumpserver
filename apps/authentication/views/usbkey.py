# -*- coding: utf-8 -*-
#

from __future__ import unicode_literals
from django.views.generic.edit import FormView
from django.shortcuts import redirect

from common.utils import get_logger
from .. import forms, errors, mixins
from .utils import redirect_to_guard_view

logger = get_logger(__name__)
__all__ = ['UserLoginUSBKeyView']


class UserLoginUSBKeyView(mixins.AuthMixin, FormView):
    template_name = 'authentication/login.html'
    form_class = forms.UserCheckOtpCodeForm
    redirect_field_name = 'next'

    def get(self, *args, **kwargs):
        try:
            user = self.get_user_from_session()
        except errors.SessionEmptyError:
            return redirect_to_guard_view('session_empty')

        try:
            self._check_if_no_active_mfa(user)
        except errors.MFAUnsetError as e:
            return redirect(e.url + '?_=login_mfa')

        return super().get(*args, **kwargs)

