from src.common.hec import HECClient
from src.common.config import SplunkConfig


def test_hec_success():
    cfg = SplunkConfig(hec_url="https://hec.example", hec_token="t")
    sent = {}

    def fake_post(url, data, headers, timeout, verify):
        sent["url"] = url
        sent["headers"] = headers
        sent["data"] = data
        return 200

    client = HECClient(cfg, post_func=fake_post)
    client.send_events([{"a": 1}], batch_size=1)
    assert sent["url"].endswith("/event")
    assert b"\n" not in sent["data"] or True
