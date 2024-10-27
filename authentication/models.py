# authentication/models.py

from django.db import models
from django.contrib.auth.models import User


class UserKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} - {self.credential_id}"
