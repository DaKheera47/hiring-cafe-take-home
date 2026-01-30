import httpx
import asyncio
import random
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class AsyncClient:
    """High-performance Async HTTP client with exponential backoff and rate-limit handling."""

    def __init__(self, timeout: int = 20, max_connections: int = 100):
        self.limits = httpx.Limits(
            max_connections=max_connections, max_keepalive_connections=20
        )
        self.timeout = httpx.Timeout(timeout)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        self.client = httpx.AsyncClient(
            limits=self.limits,
            timeout=self.timeout,
            headers=self.headers,
            follow_redirects=True,
            verify=False,  # Avature portals often have tricky SSL setups
        )

    async def get(
        self, url: str, max_retries: int = 3, **kwargs
    ) -> Optional[httpx.Response]:
        """Fetches a URL with automatic retries for rate-limiting (406, 429)."""
        retry_delay = 2.0  # Initial delay in seconds

        for attempt in range(max_retries + 1):
            try:
                response = await self.client.get(url, **kwargs)

                if response.status_code == 200:
                    return response

                if response.status_code == 404:
                    return None

                # Handling 406 (Not Acceptable) and 429 (Too Many Requests)
                if response.status_code in [406, 429]:
                    if attempt < max_retries:
                        # Exponential backoff with jitter
                        sleep_time = retry_delay * (2**attempt) + random.uniform(0, 1)
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
