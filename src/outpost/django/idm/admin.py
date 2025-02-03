from django.contrib import admin

from . import models


@admin.register(models.LDAPTarget)
class LDAPTargetAdmin(admin.ModelAdmin):
    list_display = (
        "url",
        "username",
        "group_base",
        "user_base",
        "enabled",
    )
    list_filter = ("enabled",)
