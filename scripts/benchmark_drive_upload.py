#!/usr/bin/env python3
"""Compare upload preparation memory with synthetic data, without network I/O.

Run with the project's Python: python scripts/benchmark_drive_upload.py
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import time
import tracemalloc

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nmapui.google_drive_upload import CHUNK_BYTES, UPLOAD_ENDPOINT, upload_file


class Response:
    def __init__(self, status, headers=None, payload=None):
        self.status_code, self.headers, self.payload = status, headers or {}, payload or {}

    def json(self):
        return self.payload


class OfflineDrive:
    def __init__(self, size):
        self.size, self.max_chunk, self.chunks = size, 0, 0

    def post(self, url, **kwargs):
        assert url == UPLOAD_ENDPOINT
        return Response(200, {"Location": UPLOAD_ENDPOINT + "?upload_id=synthetic"})

    def put(self, url, data, **kwargs):
        self.max_chunk = max(self.max_chunk, len(data))
        self.chunks += 1
        end = int(kwargs["headers"]["Content-Range"].split("/")[0].split("-")[-1])
        if end + 1 < self.size:
            return Response(308, {"Range": f"bytes=0-{end}"})
        return Response(200, payload={"id": "synthetic", "size": str(self.size)})


def measure(function):
    tracemalloc.start()
    started = time.perf_counter()
    function()
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"peak_bytes": peak, "seconds": round(elapsed, 4)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=32, choices=range(1, 257), metavar="1..256")
    args = parser.parse_args()
    size = args.size_mib * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="nmapui-drive-benchmark-") as directory:
        path = Path(directory) / "synthetic.pdf"
        with path.open("wb") as source:
            source.truncate(size)

        def old_multipart():
            with path.open("rb") as source:
                request = requests.Request("POST", UPLOAD_ENDPOINT, files={"file": (path.name, source)}).prepare()
                assert isinstance(request.body, bytes)

        transport = OfflineDrive(size)
        before = measure(old_multipart)
        after = measure(lambda: upload_file(
            file_path=path, name=path.name, folder_id="synthetic", requests_module=transport,
            get_access_token=lambda refresh: "synthetic-token",
        ))
    print(json.dumps({"file_bytes": size, "old_multipart": before, "resumable": after,
                      "chunks": transport.chunks, "max_chunk_bytes": transport.max_chunk,
                      "configured_chunk_bytes": CHUNK_BYTES, "network_requests": 0}, indent=2))


if __name__ == "__main__":
    main()
