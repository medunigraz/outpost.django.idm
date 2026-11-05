import json
import logging
from hashlib import sha1

import fastjsonschema
import umsgpack
import zmq
from django.contrib.staticfiles import finders
from django.core.exceptions import BadRequest, ImproperlyConfigured
from django.utils.translation import gettext as _
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from zxcvbn import zxcvbn

from .conf import settings
from .signals import account_updated

logger = logging.getLogger(__name__)


class PasswordCheckView(APIView):

    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Test password in request:

            {
                "password":"easy_to_guess"
            }

        Test password and use additional words to be blacklisted (e.g.
        username, first or family name, ...):

            {
                "password":"easy_to_guess",
                "blacklist": [
                    "john",
                    "doe",
                    "j.doe"
                ]
            }
        """
        raw = request.data.get("password", None)
        if not raw:
            return Response()
        hashed = (
            sha1(raw.encode("utf-8"), usedforsecurity=False)
            .hexdigest()
            .upper()
            .encode("ascii")
        )
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.connect(settings.IDM_PASSWORD_BLOOM_SOCKET)
        socket.setsockopt(zmq.RCVTIMEO, settings.IDM_PASSWORD_BLOOM_TIMEOUT)
        try:
            socket.send(umsgpack.packb({"value": hashed}))
            resp = socket.recv()
        except zmq.error.Again:
            found = None
        else:
            found = umsgpack.unpackb(resp).get("found", None)

        checked = zxcvbn(raw)
        suggestions = [_(msg) for msg in checked["feedback"]["suggestions"]]
        result = {
            "leaked": found,
            "score": checked["score"],
            "guesses": checked["guesses"],
            "crack_time": checked["crack_times_display"][
                "offline_slow_hashing_1e4_per_second"
            ],
            "feedback": {
                "warning": _(checked["feedback"]["warning"]),
                "suggestions": suggestions,
            },
        }
        return Response(result)


class HookAccountView(APIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        def load_schema(method):
            name = f"idm/schemas/{self.__class__.__name__}.{method}.json"
            file = finders.find(name)
            if not file:
                raise ImproperlyConfigured(f"Unable to find JSON schema {name}")
            with open(file) as inp:
                return fastjsonschema.compile(json.load(inp))

        self.validators = {
            method: load_schema(method)
            for method in self.http_method_names
            if callable(getattr(self, method, None))
            and method in self.__class__.__dict__
        }

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        validator = self.validators.get(request.method.lower())
        try:
            validator(request.data)
        except fastjsonschema.JsonSchemaException as e:
            raise BadRequest("Malformed JSON payload")

    def post(self, request, **kwargs):
        username = request.data.get("username")
        logger.debug(f"Triggering signal for updated user {username}")
        account_updated.send(sender=self.__class__, username=username)
        return Response(status=200)
