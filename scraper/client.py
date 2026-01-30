import httpx
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class AsyncClient:
    """High-performance Async HTTP client for distributed scraping."""

    def __init__(self, timeout: int = 15, max_connections: int = 100):
        self.limits = httpx.Limits(
            max_connections=max_connections, max_keepalive_connections=20
        )
        self.timeout = httpx.Timeout(timeout)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        }
        self.client = httpx.AsyncClient(
            limits=self.limits,
            timeout=self.timeout,
            headers=self.headers,
            follow_redirects=True,
        )

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            # We use a secondary attempt with verify=False if the first fails due to SSL
            try:
                response = await self.client.get(url, **kwargs)
                if response.status_code == 200:
                    return response
                if response.status_code == 404:
                    return None
            except (
                httpx.ConnectError,
                httpx.RemoteProtocolError,
                httpx.ConnectTimeout,
            ) as e:
                logger.debug(f"Retrying {url} with relaxed SSL/timeout due to: {e}")
                # Try one more time with SSL verification disabled for enterprise portals with custom certs
                async with httpx.AsyncClient(
                    verify=False, headers=self.headers, timeout=20
                ) as backup_client:
                    response = await backup_client.get(url, **kwargs)
                    if response.status_code == 200:
                        return response

            if response.status_code != 200:
                logger.debug(f"Failed to fetch {url}: Status {response.status_code}")

        except Exception as e:
            logger.error(f"Critical error fetching {url}: {str(e)}")
        return None

    async def close(self):
        await self.client.aclose()
