import logging
import textwrap
from collections import (
    defaultdict,
    namedtuple,
)

import ldap3
from celery import shared_task
from django.db.models import Count
from django.utils import timezone
from ldap3.utils.conv import escape_filter_chars
from outpost.django.campusonline import models as campusonline
from slugify import slugify

from .conf import settings

logger = logging.getLogger(__name__)


Result = namedtuple("Result", ["success", "metadata", "entries", "parameters"])


class IDMTasks:
    @shared_task(bind=True, ignore_result=False, name=f"{__name__}.IDM:organizations")
    def organizations(task, pk, language=settings.LANGUAGE_CODE, dry_run=False):
        from . import models

        try:
            target = models.LDAPTarget.objects.get(pk=pk, enabled=True)
        except models.LDAPTarget.DoesNotExist:
            logger.error(f"Could not load LDAP target {pk}")
            return

        logger.info(f"Synchronizing organizational groups to {target}")

        ldap = ldap3.Connection(
            ldap3.Server(target.url, get_info=ldap3.ALL),
            target.username,
            target.password,
            auto_bind=True,
            auto_range=True,
            client_strategy=ldap3.SAFE_SYNC,
        )

        logger.debug(f"Searcing for existing groups {ldap}")

        entries = ldap.extend.standard.paged_search(
            search_base=target.group_base,
            search_filter="(objectClass=group)",
            search_scope=ldap3.SUBTREE,
            attributes=("member", "description"),
            paged_size=settings.IDM_LDAP_PAGE_SIZE,
            generator=True,
        )

        groups = {e.get("dn"): set(e.get("attributes").get("member")) for e in entries}

        entries = ldap.extend.standard.paged_search(
            search_base=target.user_base,
            search_filter="(objectClass=person)",
            search_scope=ldap3.SUBTREE,
            attributes=("cn",),
            paged_size=settings.IDM_LDAP_PAGE_SIZE,
            generator=True,
        )

        users = {e.get("attributes").get("cn"): e.get("dn") for e in entries}

        orgs = campusonline.Organization.objects.annotate(
            person_count=Count("persons")
        ).filter(person_count__gt=0)
        logger.debug(f"Processing {orgs.count()} organizations for {target}")

        for org in orgs:
            name = (
                org.name.get(language) if isinstance(org.name, dict) else str(org.name)
            )
            slug = escape_filter_chars(
                textwrap.shorten(
                    slugify(name),
                    width=(
                        settings.IDM_LDAP_GROUP_NAME_LENGTH - (len(str(org.pk)) + 1)
                    ),
                    placeholder="...",
                )
            )
            cn = f"{org.pk}-{slug}"
            dn = f"CN={cn},{target.group_base}"

            actual = set(
                (
                    users.get(p.username)
                    for p in org.persons.filter(employed=True)
                    if p.username in users
                )
            )
            if dn in groups:
                present = groups.pop(dn)
                delete = present - actual
                if delete:
                    logger.info("Removing members from {dn} on {target}")
                    logger.debug(f"Removed members: {delete}")
                    if not dry_run:
                        result = Result(
                            *ldap.modify(
                                dn, changes={"member": [(ldap3.MODIFY_DELETE, delete)]}
                            )
                        )
                        if not result.success:
                            logger.error(
                                f"Could not modify LDAP group {dn} on {target}: {result}"
                            )
                add = actual - present
                if add:
                    logger.info("Adding members to {dn} on {target}")
                    logger.debug(f"New members: {add}")
                    if not dry_run:
                        result = Result(
                            *ldap.modify(
                                dn, changes={"member": [(ldap3.MODIFY_ADD, add)]}
                            )
                        )
                        if not result.success:
                            logger.error(
                                f"Could not modify LDAP group {dn} on {target}: {result}"
                            )
            else:
                logger.info(f"Creating new group {dn} on {target}")
                logger.debug(f"New members: {actual}")
                if not dry_run:
                    result = Result(
                        *ldap.add(
                            dn,
                            attributes={
                                "objectClass": ["top", "group"],
                                "cn": cn,
                                "member": actual,
                                "extensionName": str(org.pk),
                                "description": set((v for v in org.name.values() if v))
                                if isinstance(org.name, dict)
                                else str(org.name),
                            },
                        )
                    )
                    if not result.success:
                        logger.error(
                            f"Could not create LDAP group {dn} on {target}: {result}"
                        )

        for dn in groups.keys():
            logger.info(f"Removing absolete group {dn} from {target}")
            if not dry_run:
                result = Result(*ldap.delete(dn))
                if not result.success:
                    logger.error(
                        f"Could not delete LDAP group {dn} on {target}: {result}"
                    )


class ThreatTasks:
    @shared_task(bind=True, ignore_result=True, name=f"{__name__}.Threat:check")
    def check(task, pk):
        from .models import Source

        try:
            source = Source.objects.get(pk=pk)
        except Source.DoesNotExist:
            return
        server = (ldap3.Server(source.target.url, get_info=ldap3.ALL),)
        ldap = ldap3.Connection(
            server,
            source.target.username,
            source.target.password,
            auto_bind=True,
            auto_range=True,
            client_strategy=ldap3.SAFE_SYNC,
        )
        found = defaultdict(list)
        for identity, password, foreign, details in source.fetch():
            entries = ldap.extend.standard.paged_search(
                search_base=source.target.user_base,
                search_filter=source.ldap_filter.format(identity=identity),
                search_scope=ldap3.SUBTREE,
                attributes=(source.ldap_uid,),
                paged_size=settings.IDM_LDAP_PAGE_SIZE,
                generator=True,
            )
            for e in entries:
                dn = e.get("dn")
                logger.debug(f"Found user in {source.target}: {dn}")
                uid = e.get("attributes").get(source.ldap_uid)
                check = ldap3.Connection(
                    server,
                    dn,
                    password,
                    auto_bind=False,
                    auto_range=True,
                    client_strategy=ldap3.SAFE_SYNC,
                )
                result = Result(*check.bind())
                if result.success:
                    found[uid].append((foreign, details))
        source.last = timezone.now()
        source.save()
        logger.debug(found.keys())
        for uid, entries in found.items():
            for responder in source.responders.filter(responder__enabled=True):
                responder.respond(uid, entries)
