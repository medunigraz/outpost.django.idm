import gc
import logging
import os

import flor
import sdnotify
import umsgpack
import zmq
from django.core.management.base import BaseCommand

from ...conf import settings

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Serve bloom filter for common passwords over ZMQ"

    def handle(self, *args, **options):
        logger.info(
            f"Starting bloom filter server on {settings.IDM_PASSWORD_BLOOM_SOCKET}"
        )
        n = sdnotify.SystemdNotifier()
        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.bind(settings.IDM_PASSWORD_BLOOM_SOCKET)
        while True:
            logger.info(f"Loading bloom filter file {settings.IDM_PASSWORD_BLOOM_FILE}")
            bf = flor.BloomFilter()
            with open(settings.IDM_PASSWORD_BLOOM_FILE, "rb") as inp:
                bf.read(inp)
            n.notify("READY=1")
            logger.info("Bloom filter is now ready, waiting for requests")
            while True:
                try:
                    raw = socket.recv()
                    message = umsgpack.unpackb(raw)
                    logger.debug(f"Received message: {message}")
                    if message.get("reset") == settings.IDM_PASSWORD_BLOOM_SECRET:
                        reply = umsgpack.packb({"reloading": True})
                        socket.send(reply)
                        break
                    found = message.get("value") in bf
                    logger.debug(f"Sending match found: {found}")
                    reply = umsgpack.packb({"found": found})
                    socket.send(reply)
                except TypeError as e:
                    logger.error(
                        "Packed data type is neither ‘bytes’ nor ‘bytearray’",
                        exc_info=e,
                    )
                except umsgpack.UnpackException as e:
                    logger.error("Could not unpack message", exc_info=e)
                except zmq.ZMQError as e:
                    logger.error("Could not send or receive over ZMQ", exc_info=e)
            n.notify("RELOADING=1")
            del bf
            gc.collect()
