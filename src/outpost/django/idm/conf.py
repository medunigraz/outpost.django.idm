from appconf import AppConf
from django.conf import settings


class IDMAppConf(AppConf):
    LDAP_PAGE_SIZE = 1000
    LDAP_GROUP_NAME_LENGTH = 64
    KADUU_OAUTH_URL = ""
    KADUU_CLIENT_ID = ""
    KADUU_CLIENT_SECRET = ""
    KADUU_SEARCH_URL = "https://app.leak.center/svc-saas/leak/search?size=200&sort=createdAt,desc&length=500&highlight=true"

    class Meta:
        prefix = "idm"
