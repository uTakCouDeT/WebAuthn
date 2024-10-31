from django.db import models
from django.contrib.auth.models import User


class WebAuthnDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="webauthn_devices")
    user_login = models.CharField(max_length=255, unique=True)
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    device_name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} ({self.user_login}) - {self.device_name}"
