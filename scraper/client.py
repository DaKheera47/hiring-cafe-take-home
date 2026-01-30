import httpx
import asyncio
import random
from typing import Optional
import logging
from user_agent import generate_user_agent

logger = logging.getLogger(__name__)


class AsyncClient:
    """High-performance Async HTTP client with exponential backoff and rate-limit handling."""

    def __init__(self, timeout: int = 30, max_connections: int = 100):
        self.limits = httpx.Limits(
            max_connections=max_connections, max_keepalive_connections=20
        )
        self.timeout = httpx.Timeout(timeout)
        self.client = httpx.AsyncClient(
            limits=self.limits,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,  # Avature portals often have tricky SSL setups
        )

    def _get_headers(self) -> dict:
        """Returns randomized headers to avoid fingerprinting."""
        # Use user-agent library for realistic desktop UAs
        ua = generate_user_agent(os=("win", "mac", "linux"), device_type="desktop")

        # Randomly choose some common browser behaviors
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

        # Add Sec-Ch-Ua headers if it's a Chrome-like UA (to be more realistic)
        if "Chrome" in ua:
            headers["Sec-Ch-Ua"] = (
                '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"'
            )
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = (
                '"Windows"' if "Windows" in ua else '"macOS"'
            )

        return headers

    async def get(
        self, url: str, max_retries: int = 4, **kwargs
    ) -> Optional[httpx.Response]:
        """Fetches a URL with automatic retries for rate-limiting (406, 429)."""
        retry_delay = 5.0  # Increased initial delay

        for attempt in range(max_retries + 1):
            # Small random delay before EVERY request to avoid bursty patterns
            await asyncio.sleep(random.uniform(0.5, 2.0))

            try:
                headers = self._get_headers()
                if "headers" in kwargs:
                    headers.update(kwargs.pop("headers"))

                response = await self.client.get(url, headers=headers, **kwargs)

                if response.status_code == 200:
                    return response

                if response.status_code == 404:
                    return None

                # Handling 406 (Not Acceptable) and 429 (Too Many Requests)
                if response.status_code in [406, 403, 429]:
                    if attempt < max_retries:
                        # Exponential backoff with significant jitter
                        sleep_time = retry_delay * (2**attempt) + random.uniform(2, 5)
                        logger.warning(
                            f"Rate limited ({response.status_code}) on {url}. Retrying in {sleep_time:.2f}s (Attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(sleep_time)
                        continue
                    else:
                        logger.error(
                            f"Failed to fetch {url} after {max_retries} retries due to rate limiting ({response.status_code})."
                        )
                        return None

                logger.debug(f"Non-success status {response.status_code} for {url}")
                return None

            except (httpx.RequestError, httpx.HTTPError) as e:
                if attempt < max_retries:
                    sleep_time = retry_delay * (2**attempt)
                    logger.debug(
                        f"Network error on {url}: {str(e)}. Retrying in {sleep_time}s..."
                    )
                    await asyncio.sleep(sleep_time)
                    continue
                else:
                    logger.error(
                        f"Critical error fetching {url} after retries: {str(e)}"
                    )
                    return None
            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {str(e)}")
                return None

        return None

    async def close(self):
        await self.client.aclose()
