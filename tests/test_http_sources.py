"""Rate-floor and open-PR index behaviour, without network access."""
import io
import json

import pytest

from ghsi import http, sources


class _Resp(io.BytesIO):
    def __init__(self, body, headers):
        super().__init__(json.dumps(body).encode())
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _serve(monkeypatch, tmp_path, headers, body=None):
    monkeypatch.setattr(http, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(http.urllib.request, "urlopen", lambda req, timeout=30: _Resp(body or [], headers))


def test_search_bucket_does_not_trip_the_core_floor(monkeypatch, tmp_path):
    _serve(monkeypatch, tmp_path, {"x-ratelimit-remaining": "28", "x-ratelimit-resource": "search"}, {"items": []})
    assert http.get_json("https://api.github.com/search/issues?q=x", ttl=0) == {"items": []}


def test_core_bucket_below_floor_stops(monkeypatch, tmp_path):
    _serve(monkeypatch, tmp_path, {"x-ratelimit-remaining": "10", "x-ratelimit-resource": "core"})
    with pytest.raises(http.RateLimitLow):
        http.get_json("https://api.github.com/advisories", ttl=0)


def test_open_pr_index_keys_on_title_ghsa(monkeypatch):
    pages = [
        {"number": 1, "title": "[GHSA-26mh-57q7-jfvr] PraisonAI ...", "html_url": "u1"},
        {"number": 2, "title": "Bump something", "html_url": "u2"},
    ]
    monkeypatch.setattr(sources, "_OPEN_PR_INDEX", None)
    monkeypatch.setattr(sources, "get_json", lambda *a, **k: (pages, {}))
    assert [p["number"] for p in sources.open_prs_for("GHSA-26mh-57q7-jfvr")] == [1]
    assert sources.open_prs_for("GHSA-xxxx-xxxx-xxxx") == []
