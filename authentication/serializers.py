from rest_framework import serializers
from .models import WebAuthnDevice


class WebAuthnDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebAuthnDevice
        fields = ['user_login', 'credential_id', 'public_key', 'sign_count', 'device_name']
