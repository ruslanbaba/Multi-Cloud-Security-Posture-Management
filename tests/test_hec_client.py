from __future__ import annotations

from typing import Dict, List

from src.common.config import SplunkConfig
from src.common.hec import HECClient


class Recorder:
    def __init__(self):
        self.posts: List[Dict] = []

    def post(self, url: str, data: bytes, headers: Dict[str, str], timeout: float, verify: bool) -> int:
        self.posts.append({"url": url, "data": data.decode("utf-8"), "headers": headers, "timeout": timeout, "verify": verify})
        return 200


def test_hec_batching_sends_multiple_lines():
    cfg = SplunkConfig(hec_url="https://example", hec_token="t")
    rec = Recorder()
    client = HECClient(cfg, post_func=rec.post)
    events = [{"a": 1}, {"b": 2}, {"c": 3}]
    client.send_events(events, batch_size=2)
    assert len(rec.posts) == 2
    assert "\n" in rec.posts[0]["data"]
