import pytest

from nmapui import google_drive_upload as uploads


SESSION = uploads.UPLOAD_ENDPOINT + "?upload_id=private-session"


class Response:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.payload = payload or {}

    def json(self):
        return self.payload


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads.time, "sleep", lambda seconds: None)
    file_path = tmp_path / "report.pdf"
    file_path.write_bytes(b"abcdefgh")
    return file_path


def run_upload(path, transport, get_token=lambda refresh: "token"):
    return uploads.upload_file(
        file_path=path, name="report.pdf", folder_id="folder", requests_module=transport,
        get_access_token=get_token,
    )


class Transport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.puts = []
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return Response(headers={"Location": SESSION})

    def put(self, url, **kwargs):
        assert url == SESSION
        assert kwargs["allow_redirects"] is False
        self.puts.append(kwargs)
        item = next(self.responses)
        if isinstance(item, Exception):
            raise item
        return item


def test_partial_commit_after_connection_failure_uses_confirmed_offset(artifact):
    transport = Transport([
        OSError("connection lost, session=must-not-leak"),
        Response(308, headers={"Range": "bytes=0-2"}),
        Response(payload={"id": "file", "size": "8"}),
    ])
    assert run_upload(artifact, transport)["id"] == "file"
    assert [request["headers"]["Content-Range"] for request in transport.puts] == [
        "bytes 0-7/8", "bytes */8", "bytes 3-7/8",
    ]
    assert transport.puts[-1]["data"] == b"defgh"
    assert len(transport.posts) == 1


def test_ambiguous_completion_is_probed_without_creating_a_second_file(artifact):
    transport = Transport([OSError("response lost"), Response(payload={"id": "already-complete"})])
    assert run_upload(artifact, transport)["id"] == "already-complete"
    assert len(transport.posts) == 1
    assert transport.puts[-1]["data"] == b""


def test_large_file_has_bounded_chunks_and_honors_server_acknowledgements(artifact, monkeypatch):
    monkeypatch.setattr(uploads, "CHUNK_BYTES", 256 * 1024)
    block = b"a" * uploads.CHUNK_BYTES
    artifact.write_bytes(block * 3 + b"tail")
    transport = Transport([
        Response(308, headers={"Range": f"bytes=0-{uploads.CHUNK_BYTES - 1}"}),
        Response(308, headers={"Range": f"bytes=0-{2 * uploads.CHUNK_BYTES - 1}"}),
        Response(308, headers={"Range": f"bytes=0-{3 * uploads.CHUNK_BYTES - 1}"}),
        Response(payload={"id": "file", "size": str(artifact.stat().st_size)}),
    ])
    assert run_upload(artifact, transport)["id"] == "file"
    assert [len(request["data"]) for request in transport.puts] == [len(block)] * 3 + [4]
    assert b"".join(request["data"] for request in transport.puts) == block * 3 + b"tail"


def test_server_rejection_refreshes_access_token_once(artifact):
    tokens = []

    def get_token(refresh):
        tokens.append(refresh)
        return "refreshed" if refresh else "original"

    transport = Transport([Response(401), Response(payload={"id": "file"})])
    run_upload(artifact, transport, get_token)
    assert tokens == [False, True]
    assert [request["headers"]["Authorization"] for request in transport.puts] == [
        "Bearer original", "Bearer refreshed",
    ]


@pytest.mark.parametrize("url", [
    "http://www.googleapis.com/upload/drive/v3/files?upload_id=secret",
    "https://www.googleapis.com.attacker.test/upload/drive/v3/files",
    "https://user:pass@www.googleapis.com/upload/drive/v3/files",
    "https://www.googleapis.com:8443/upload/drive/v3/files",
    "https://www.googleapis.com/other",
    "//attacker.test/secret",
])
def test_untrusted_session_url_never_receives_file_or_bearer_token(artifact, url):
    class UntrustedTransport(Transport):
        def post(self, *args, **kwargs):
            return Response(headers={"Location": url})

    transport = UntrustedTransport([])
    with pytest.raises(RuntimeError, match="invalid upload session URL"):
        run_upload(artifact, transport)
    assert not transport.puts


@pytest.mark.parametrize("response", [
    Response(200, payload={}),
    Response(200, payload={"id": "file", "size": "7"}),
    Response(308, headers={"Range": "bytes=2-3"}),
    Response(308, headers={"Range": "bytes=0-900"}),
    Response(308, headers={"Range": "bytes=0-7"}),
    Response(302, headers={"Location": "https://attacker.test"}),
    Response(403, payload={"error": "permission denied"}),
    Response(404),
])
def test_invalid_completion_and_permanent_errors_fail_without_restart(artifact, response):
    transport = Transport([response])
    with pytest.raises(RuntimeError):
        run_upload(artifact, transport)
    assert len(transport.posts) == len(transport.puts) == 1


def test_rate_limit_probes_upload_before_resending_bytes(artifact):
    transport = Transport([
        Response(403, payload={"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}),
        Response(308), Response(payload={"id": "file"}),
    ])
    assert run_upload(artifact, transport)["id"] == "file"
    assert transport.puts[1]["headers"]["Content-Range"] == "bytes */8"


def test_repeated_network_failures_are_bounded_and_do_not_leak_session(artifact):
    transport = Transport([OSError(SESSION)] * uploads.MAX_FAILURES)
    with pytest.raises(RuntimeError, match="upload interrupted") as error:
        run_upload(artifact, transport)
    assert "private-session" not in str(error.value)
    assert len(transport.puts) == uploads.MAX_FAILURES


def test_repeated_zero_progress_is_bounded(artifact):
    transport = Transport([Response(308)] * uploads.MAX_FAILURES)
    with pytest.raises(RuntimeError, match="upload interrupted"):
        run_upload(artifact, transport)
    assert len(transport.puts) == uploads.MAX_FAILURES


def test_empty_file_is_finalized_and_confirmed(artifact):
    artifact.write_bytes(b"")
    transport = Transport([Response(payload={"id": "empty", "size": "0"})])
    assert run_upload(artifact, transport)["id"] == "empty"
    assert transport.puts[0]["headers"]["Content-Range"] == "bytes */0"


def test_growing_report_never_sends_bytes_beyond_announced_size(artifact):
    class GrowingTransport(Transport):
        def post(self, url, **kwargs):
            with artifact.open("ab") as report:
                report.write(b"more")
            return super().post(url, **kwargs)

    transport = GrowingTransport([])
    with pytest.raises(RuntimeError, match="File changed"):
        run_upload(artifact, transport)
    assert not transport.puts
