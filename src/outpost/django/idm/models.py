import itertools
import logging
import re

from django.contrib.postgres.fields import JSONField
from django.core.mail import EmailMessage
from django.db import models
from django.template import (
    Context,
    Template,
)
from django.utils.translation import gettext as _
from jira import JIRA
from oauthlib.oauth2 import LegacyApplicationClient
from ordered_model.models import OrderedModel
from outpost.django.base.decorators import signal_connect
from polymorphic.models import PolymorphicModel
from purl import URL
from requests_oauthlib import OAuth2Session
from requests_toolbelt.sessions import BaseUrlSession
from sqlalchemy import (
    create_engine,
    text,
)

from .conf import settings

# import ollama


logger = logging.getLogger(__name__)


class LDAPTarget(models.Model):
    url = models.CharField(max_length=512)
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256)
    group_base = models.CharField(max_length=1024)
    user_base = models.CharField(max_length=1024)
    enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.url


class Source(PolymorphicModel):
    name = models.CharField(max_length=128)
    target = models.ForeignKey(LDAPTarget, null=True, on_delete=models.SET_NULL)
    ldap_filter = models.TextField()
    ldap_uid = models.CharField(max_length=256)
    last = models.DateTimeField(editable=False, auto_now_add=True)

    def __str__(self):
        return str(self.name)

    def fetch(self):
        raise NotImplementedError(_("Subclasses must implement this method"))


class KaduuSource(Source):
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256)
    domain = models.CharField(max_length=512)

    def __str__(self):
        return str(self.name)

    def fetch(self):
        session = OAuth2Session(
            client=LegacyApplicationClient(client_id=settings.IDM_KADUU_CLIENT_ID)
        )
        logger.debug(f"Fetching OAuth2 token from {settings.IDM_KADUU_OAUTH_URL}")
        session.fetch_token(
            token_url=settings.IDM_KADUU_OAUTH_URL,
            username=self.username,
            password=self.password,
            client_id=settings.IDM_KADUU_CLIENT_ID,
            client_secret=settings.IDM_KADUU_CLIENT_SECRET,
        )
        last = self.last.strftime("%Y-%m-%d")
        url = URL(settings.IDM_KADUU_SEARCH_URL).query_param(
            "query", f"{self.domain} AND createdAt:[{last} TO *]"
        )
        extractors = list(self.extractors.filter(extractor__enabled=True))
        for page in itertools.count():
            with session.get(url.query_param("page", page).as_string()) as response:
                logger.debug(f"Requested data from {response.url}")
                response.raise_for_status()
                data = response.json()
                for entry in data.get("content", []):
                    for x in extractors:
                        match = x.extract(entry.get("content"))
                        if match:
                            identity, secret, context = match
                            yield (
                                identity,
                                secret,
                                entry.get("id"),
                                {
                                    "context": context,
                                    "filename": entry.get("fileName"),
                                    "leak": entry.get("leakId"),
                                    "source": entry.get("leakSource"),
                                    "tags": entry.get("leakTags").split(",")
                                    if entry.get("leakTags")
                                    else None,
                                    "cvss": entry.get("cvssScore"),
                                    "published": entry.get("leakPublishDate"),
                                    "discovered": entry.get("leakDiscoverDate"),
                                },
                            )
                            continue
                if data.get("last"):
                    return


class Extractor(PolymorphicModel):
    name = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)

    def prepare(self, source):
        pass

    def extract(self, raw):
        raise NotImplementedError(_("Subclasses must implement this method"))

    def __str__(self):
        return self.name


@signal_connect
class SourceExtractor(OrderedModel):
    source = models.ForeignKey(
        Source, on_delete=models.CASCADE, related_name="extractors"
    )
    extractor = models.ForeignKey(
        Extractor, on_delete=models.CASCADE, related_name="sources"
    )

    order_with_respect_to = "source"

    def __str__(self):
        return f"{self.extractor}@{self.source}"

    def post_init(self, *args, **kwargs):
        extractor = getattr(self, "extractor", None)
        if extractor:
            extractor.prepare(self.source)

    def extract(self, raw):
        return self.extractor.extract(raw)


@signal_connect
class LanguageModelExtractor(Extractor):
    url = models.URLField()
    token = models.TextField()
    model = models.CharField(max_length=128)
    prompt = models.TextField()

    def post_init(self, *args, **kwargs):
        self._session = BaseUrlSession(base_url=self.url)
        self._session.headers["Authorization"] = f"Bearer {self.token}"
        self._session.headers["Content-Type"] = "application/json"
        self._format = {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "description": "Identity and secret represening a user",
            "type": "object",
            "properties": {
                "found": {"type": "boolean"},
                "result": {
                    "type": "object",
                    "properties": {
                        "identity": {"type": "string", "minLength": 1},
                        "secret": {"type": "string", "minLength": 1},
                    },
                    "required": ["identity", "secret"],
                },
            },
            "required": ["found", "result"],
        }

    def prepare(self, source):
        self._source = source

    def extract(self, raw):
        payload = {
            "model": self.model,
            "prompt": self.prompt.format(source=self._source, raw=raw)
            + "\nRespond using JSON.",
            "format": self._format,
            "stream": False,
        }
        with self._session.post("api/generate", json=payload) as response:
            response.raise_for_status()
            answer = response.json()
            if answer.get("found"):
                return (
                    answer.get("result").get("identity"),
                    answer.get("result").get("secret"),
                )


@signal_connect
class RegularExpressionExtractor(Extractor):

    expressions = models.TextField()
    multiline = models.BooleanField(default=False)
    ignore_case = models.BooleanField(default=False)

    def prepare(self, source):
        flags = (re.IGNORECASE if self.ignore_case else 0) | (
            re.MULTILINE if self.multiline else 0
        )
        self._condition = re.compile(rf"<kaduu:h>.*{source.domain}</kaduu:h>")
        self._cleanup = re.compile(r"</?kaduu:h>")
        self._patterns = [
            re.compile(line.format(source=source), flags=flags)
            for line in self.expressions.splitlines()
        ]

    def extract(self, raw):
        for line in raw.splitlines():
            if not self._condition.match(line):
                continue
            for p in self._patterns:
                cleaned = self._cleanup.sub("", line)
                match = p.match(cleaned)
                if match:
                    return (match.group("identity"), match.group("secret"), cleaned)


class Responder(PolymorphicModel):
    name = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    def run(self, source, uid, entries):
        raise NotImplementedError(_("Subclasses must implement this method"))


class SourceResponder(OrderedModel):
    source = models.ForeignKey(
        Source, on_delete=models.CASCADE, related_name="responders"
    )
    responder = models.ForeignKey(
        Responder, on_delete=models.CASCADE, related_name="sources"
    )

    order_with_respect_to = "source"

    def __str__(self):
        return f"{self.responder}@{self.source}"

    def respond(self, uid, entries):
        return self.responder.run(self.source, uid, entries)


class JIRAResponder(Responder):
    url = models.URLField()
    token = models.TextField()
    project = models.CharField(max_length=256)
    summary = models.TextField()
    description = models.TextField()
    issuetype = models.CharField(max_length=128)
    defaults = JSONField()

    def run(self, source, uid, entries):
        jira = JIRA(server=self.url, token_auth=self.token)
        context = Context(
            {
                "source": source,
                "uid": uid,
                "entries": entries,
            }
        )
        fields = dict(
            **self.defaults,
            **{
                "project": self.project,
                "summary": Template(self.summary).render(context),
                "description": Template(self.description).render(context),
                "issuetype": self.issuetype,
            },
        )
        issue = jira.create_issue(fields=fields)
        logger.debug(f"Created new JIRA issue: {issue.permalink()}")


class IncidentResponder(Responder):
    def run(self, source, uid, entries):
        for foreign, details in entries:
            incident, created = Incident.objects.get_or_create(
                source=source,
                user=uid,
                foreign=foreign,
                defaults={
                    "details": details,
                },
            )
            if created:
                logger.info(f"Created new incident {incident}")
            else:
                logger.info(f"Updated existing incident {incident}")


class MailResponder(Responder):
    sender = models.EmailField()
    subject = models.CharField(max_length=256)
    template = models.TextField()

    def run(self, source, uid, entries):
        context = Context(
            {
                "source": source,
                "uid": uid,
                "entries": entries,
            }
        )
        for recipient in self.recipients.all():
            email = EmailMessage(
                Template(self.subject).render(context),
                Template(self.template).render(context),
                self.sender,
                [recipient.mail],
            )
            logger.debug(f"Mail responder sending to {recipient}")
            email.send()


class MailResponderRecipient(models.Model):
    responder = models.ForeignKey(
        MailResponder, on_delete=models.CASCADE, related_name="recipients"
    )
    name = models.CharField(max_length=256)
    mail = models.EmailField()

    def __str__(self):
        return f"{self.name} <{self.mail}>"


class SQLResponder(Responder):
    url = models.CharField(max_length=256)
    query = models.TextField()

    def run(self, source, uid, entries):
        engine = create_engine(self.url, max_identifier_length=128)
        context = {
            "uid": uid,
            "entries": entries,
        }
        with engine.connect() as connection:
            result = connection.execute(text(self.query), context)
            if result.rowcount:
                logger.debug(f"SQL responder returned {result.fetchall()}")
            else:
                logger.debug(f"SQL responder returned no data")


class Incident(models.Model):
    source = models.ForeignKey(Source, null=True, on_delete=models.SET_NULL)
    foreign = models.TextField(db_index=True)
    user = models.TextField()
    on = models.DateTimeField(auto_now_add=True)
    details = JSONField()

    def __str__(self):
        return f"{self.source}: {self.user}"
