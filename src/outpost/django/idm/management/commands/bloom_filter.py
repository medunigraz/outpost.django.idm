import logging
import math
import os
from collections.abc import Iterator
from pathlib import Path

import umsgpack
import zmq
from django.core.management.base import BaseCommand
from flor import BloomFilter

from ...conf import settings

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Build bloom filter"

    def handle(self, *args, **options):

        def iter_input_files(input_dir: Path) -> Iterator[os.DirEntry]:
            with os.scandir(input_dir) as entries:
                for entry in entries:
                    yield entry

        def iter_hashes_from_file(path: str, filename: str) -> Iterator[bytes]:
            prefix = filename.encode("ascii")
            buffer_size = 64 * 1024
            with open(path, "rb", buffering=buffer_size) as f:
                for line in f:
                    yield prefix + line[:35]

        def count_hashes(input_dir: Path) -> int:
            logger.debug("Start counting SHA-1 hashes")

            chunk_size = 1024 * 1024

            hashes = 0
            files = 0

            for entry in iter_input_files(input_dir):
                files += 1
                last_byte = 10

                with open(entry.path, "rb", buffering=0) as f:
                    while chunk := f.read(chunk_size):
                        hashes += chunk.count(b"\n")
                        last_byte = chunk[-1]

                if last_byte != 10:
                    hashes += 1

            logger.debug("Files: %s", f"{files:,}")
            logger.debug("Hashes: %s", f"{hashes:,}")

            return hashes

        def build_bloomfilter(hash_count: int) -> None:
            logger.info("Start building BloomFilter")

            capacity = math.ceil(
                hash_count * settings.IDM_PASSWORD_BLOOM_CAPACITY_SAFETY_FACTOR
            )

            logger.debug("Bloom capacity: %s", f"{capacity:,}")

            bf = BloomFilter(
                n=capacity, p=settings.IDM_PASSWORD_BLOOM_FALSE_POSITIVE_RATE
            )

            logger.debug("BloomFilter initialized")
            logger.debug("Bloom bits: %s", f"{bf.m:,}")
            logger.debug("Actual bytes: %s", f"{bf.M:,}")
            logger.debug("Actual GiB: %.2f", bf.M / 1024**3)
            logger.debug("Actual hash functions: %s", f"{bf.k:,}")

            hashes = 0
            files = 0

            for entry in iter_input_files(settings.IDM_PASSWORD_BLOOM_INPUT_DIR):
                files += 1

                for value in iter_hashes_from_file(
                    entry.path,
                    entry.name,
                ):
                    bf.add(value)
                    hashes += 1

                    if hashes % 10_000_000 == 0:
                        logger.debug(
                            "Inserted %s hashes from %s files",
                            f"{hashes:,}",
                            f"{files:,}",
                        )
            logger.debug(
                "Inserted %s hashes from %s files",
                f"{hashes:,}",
                f"{files:,}",
            )

            if hashes > capacity:
                logger.warning(
                    "Inserted hashes exceeded Bloom filter capacity. "
                    "The false-positive rate may be worse than requested."
                )

            with open(settings.IDM_PASSWORD_BLOOM_FILE, "wb") as f:
                bf.write(f)

            logger.info("BloomFilter build finished")

        def reload_bloomfilter() -> None:
            logger.info("Requesting BloomFilter reload")

            context = zmq.Context()
            socket = context.socket(zmq.REQ)

            try:
                socket.connect(settings.IDM_PASSWORD_BLOOM_SOCKET)
                message = {"reset": settings.IDM_PASSWORD_BLOOM_SECRET}
                socket.send(umsgpack.packb(message))

                reply = umsgpack.unpackb(socket.recv())

                if reply.get("reloading") is not True:
                    raise RuntimeError(
                        f"Unexpected BloomFilter reload response: {reply}"
                    )

                logger.info("BloomFilter reload requested successfully")

            finally:
                socket.close()
                context.term()

        hash_count = count_hashes(settings.IDM_PASSWORD_BLOOM_INPUT_DIR)

        try:
            build_bloomfilter(hash_count)
        except Exception as e:
            logger.error("BloomFilter build failed", exc_info=e)
            raise

        reload_bloomfilter()
