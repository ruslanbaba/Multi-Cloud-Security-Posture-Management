from __future__ import annotations

import json
import time
from typing import Callable, Dict, Iterable, List, Optional
import logging
import ssl
from urllib import request, error

from .config import SplunkConfig


logger = logging.getLogger("mcspm.hec")


class HECClient:
    def __init__(self, cfg: SplunkConfig, post_func: Optional[Callable[[str, bytes, Dict[str, str], float, bool], int]] = None) -> None:
        self.cfg = cfg
        self._post_func = post_func or self._http_post

    def _event_payload(self, event: Dict) -> Dict:
        payload: Dict[str, object] = {
            "event": event,
            "source": self.cfg.hec_source,
            "sourcetype": self.cfg.hec_sourcetype,
        }
        if self.cfg.hec_index:
            payload["index"] = self.cfg.hec_index
        return payload

    def send_events(self, events: Iterable[Dict], batch_size: int = 100, max_retries: int = 3, backoff: float = 1.0) -> None:
        batch: List[Dict] = []
        for ev in events:
            batch.append(self._event_payload(ev))
            if len(batch) >= batch_size:
                self._post_batch(batch, max_retries=max_retries, backoff=backoff)
                batch = []
        if batch:
            self._post_batch(batch, max_retries=max_retries, backoff=backoff)

    def _http_post(self, url: str, data: bytes, headers: Dict[str, str], timeout: float, verify: bool) -> int:
        ctx = None
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = request.Request(url, data=data, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return int(resp.getcode())
        except error.HTTPError as e:
            return int(e.code)
        except Exception as e:
            logger.error("HTTP post failed: %s", e)
            return 0

    def _post_batch(self, batch: List[Dict], max_retries: int, backoff: float) -> None:
        data = "\n".join(json.dumps(item, separators=(",", ":")) for item in batch).encode("utf-8")
        url = f"{self.cfg.hec_url.rstrip('/')}/event"
        headers = {
            "Authorization": f"Splunk {self.cfg.hec_token}",
            "Content-Type": "application/json",
        }
        attempt = 0
        while True:
            attempt += 1
            status = self._post_func(url, data, headers, 15.0, self.cfg.verify_tls)
            if 200 <= status < 300:
                logger.debug("Sent %d events to HEC", len(batch))
                return
            else:
                logger.warning("HEC non-success status=%s", status)
            if attempt >= max_retries:
                raise RuntimeError(f"Failed to send batch to HEC after {attempt} attempts")
            sleep_for = backoff * (2 ** (attempt - 1))
            time.sleep(min(sleep_for, 30))
