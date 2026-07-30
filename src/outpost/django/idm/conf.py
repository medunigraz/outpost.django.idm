from datetime import timedelta
from pathlib import Path

from appconf import AppConf
from django.conf import settings


class IDMAppConf(AppConf):
    LDAP_PAGE_SIZE = 1000
    LDAP_GROUP_NAME_LENGTH = 64
    KADUU_OAUTH_URL = ""
    KADUU_CLIENT_ID = ""
    KADUU_CLIENT_SECRET = ""  # nosec B105
    KADUU_SEARCH_URL = "https://app.leak.center/svc-saas/leak/search?size=200&sort=createdAt,desc&length=500&highlight=true"
    USER_THREAT_THRESHOLD = 30
    PASSWORD_BLOOM_SOCKET = "ipc:///run/outpost/bloom.socket"  # nosec B105
    PASSWORD_BLOOM_TIMEOUT = int(timedelta(seconds=2).total_seconds() * 1000)
    PASSWORD_BLOOM_FILE = str(
        Path(settings.MEDIA_ROOT).joinpath("idm", "haveibeenpwned.flor")
    )

    class Meta:
        prefix = "idm"
