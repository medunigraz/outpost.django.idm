from django.db import models


class LDAPTarget(models.Model):
    url = models.CharField(max_length=512)
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256)
    group_base = models.CharField(max_length=1024)
    user_base = models.CharField(max_length=1024)
    enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.url
