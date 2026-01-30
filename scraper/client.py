import asyncio
import random
from typing import Optional
import logging
from user_agent import generate_user_agent
import tls_client

logger = logging.getLogger(__name__)

# Realistic browser identifiers for tls-client
CLIENT_IDENTIFIERS = [
    "chrome_120",
    "chrome_119",
    "firefox_120",
    "firefox_117",
    "opera_90",
    "safari_15_6_1",
]


class AsyncClient:
    """Async wrapper for tls-client to provide browser-grade TLS fingerprints."""

    def __init__(self, timeout: int = 30, max_connections: int = 100):
        self.timeout = timeout
        self.max_connections = max_connections
        # tls-client session is sync, we'll use a pool-like approach
        self._sessions = []
        for _ in range(5):  # Create a small pool of sessions
            session = tls_client.Session(
                client_identifier=random.choice(CLIENT_IDENTIFIERS),
                random_tls_extension_order=True,
            )
            self._sessions.append(session)

    def _get_headers(self, ua: str) -> dict:
        """Returns randomized headers to avoid fingerprinting."""
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": random.choice(
                ["en-US,en;q=0.9", "en-GB,en;q=0.8,en;q=0.7", "en-US,en;q=0.5"]
            ),
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://www.google.com/",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        if "Chrome" in ua:
            headers["Sec-Ch-Ua"] = (
                '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"'
            )
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = (
                '"Windows"' if "Windows" in ua else '"macOS"'
            )

        return headers

    async def get(self, url: str, max_retries: int = 4, **kwargs) -> Optional[any]:
        """Fetches a URL with automatic retries for rate-limiting (406, 429)."""
        retry_delay = 5.0

        for attempt in range(max_retries + 1):
            await asyncio.sleep(random.uniform(1.0, 3.0))

            try:
                ua = generate_user_agent(
                    os=("win", "mac", "linux"), device_type="desktop"
                )
                headers = self._get_headers(ua)
                if "headers" in kwargs:
                    headers.update(kwargs.pop("headers"))

                # Choose a random session from our pool
                session = random.choice(self._sessions)

                # Convert httpx-style timeout to tls-client style
                timeout_val = kwargs.pop("timeout", self.timeout)
                if isinstance(timeout_val, (int, float)):
                    timeout_seconds = int(timeout_val)
                else:
                    # Handle httpx.Timeout objects if they sneak in
                    timeout_seconds = (
                        getattr(timeout_val, "connect", self.timeout) or self.timeout
                    )

                # tls-client is sync, so we run it in a thread
                response = await asyncio.to_thread(
                    session.get,
                    url,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                    allow_redirects=kwargs.pop("follow_redirects", True),
                    **kwargs,
                )

                if response.status_code == 200:
                    logger.info(f"Successfully fetched {url} (200 OK)")
                    return response

                if response.status_code == 404:
                    return None

                if response.status_code in [406, 403, 429]:
                    if attempt < max_retries:
                        sleep_time = retry_delay * (2**attempt) + random.uniform(2, 5)
                        logger.warning(
                            f"Rate limited ({response.status_code}) on {url}. Retrying in {sleep_time:.2f}s (Attempt {attempt + 1}/{max_retries})"
                        )
                        # Rotate session on block
                        try:
                            self._sessions.remove(session)
                        except ValueError:
                            pass
                        self._sessions.append(
                            tls_client.Session(
                                client_identifier=random.choice(CLIENT_IDENTIFIERS),
                                random_tls_extension_order=True,
                            )
                        )
                        await asyncio.sleep(sleep_time)
                        continue
                    else:
                        logger.error(
                            f"Failed to fetch {url} after {max_retries} retries ({response.status_code})."
                        )
                        return None

                return None

            except Exception as e:
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay * (2**attempt))
                    continue
                logger.error(f"Error fetching {url}: {str(e)}")
                return None

        return None

    async def close(self):
        # tls-client sessions don't need explicit close like httpx
        pass
