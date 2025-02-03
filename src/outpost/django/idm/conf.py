from appconf import AppConf
from django.conf import settings


class IDMAppConf(AppConf):
    LDAP_PAGE_SIZE = 1000
    LDAP_GROUP_NAME_LENGTH = 64

    class Meta:
        prefix = "idm"
