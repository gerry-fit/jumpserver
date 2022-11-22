# -*- coding: utf-8 -*-
#
from django.urls import path

from .views import UsbKeyChallenge

urlpatterns = [
    path('challenge/', UsbKeyChallenge.as_view(), name='challenge'),
]