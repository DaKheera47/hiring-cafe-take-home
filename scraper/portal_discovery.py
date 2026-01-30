from urllib.parse import urlparse
import logging
import asyncio
from typing import Set, Optional, List
import httpx

logger = logging.getLogger(__name__)


class PortalDiscovery:
    """Discovers and normalizes Avature portal domains."""

    @staticmethod
    def normalize_to_base(url: str) -> Optional[str]:
        """Extracts clean base URL (e.g., https://company.avature.net)."""
        if not url:
            return None
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
            if "avature.net" in parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
        return None

    async def discover_from_ct_logs(self) -> Set[str]:
        """Query Certificate Transparency logs for *.avature.net using curl_cffi for better fingerprinting."""
        from curl_cffi.requests import AsyncSession

        logger.info("Querying Certificate Transparency logs for new portals...")
        domains = set()

        # crt.sh is very sensitive to fingerprints and often throws 503s
        for attempt in range(1, 4):
            try:
                async with AsyncSession(impersonate="chrome") as session:
                    url = "https://crt.sh/?q=%.avature.net&output=json"
                    logger.info(f"CT logs attempt {attempt}/3...")

                    resp = await session.get(url, timeout=60)

                    if resp.status_code == 200:
                        data = resp.json()
                        for entry in data:
                            name = entry.get("name_value", "").lower()
                            for subname in name.split("\n"):
                                if subname.startswith("*."):
                                    subname = subname[2:]
                                if subname.endswith(".avature.net"):
                                    domains.add(f"https://{subname}")

                        logger.info(
                            f"CT logs successful: found {len(domains)} raw domains."
                        )
                        return domains
                    elif resp.status_code == 503:
                        logger.warning(
                            f"CT logs returned 503 (Attempt {attempt}). Backing off..."
                        )
                        await asyncio.sleep(attempt * 5)
                    else:
                        logger.warning(f"CT logs returned status {resp.status_code}")

            except Exception as e:
                logger.error(f"CT log discovery attempt {attempt} failed: {e}")
                await asyncio.sleep(attempt * 2)

        return domains

    async def validate_portals(
        self, urls: List[str], concurrency: int = 10
    ) -> List[str]:
        """Validates portals in parallel to ensure they are active Avature sites."""
        logger.info(f"Validating {len(urls)} portals with concurrency={concurrency}...")
        valid_urls = []
        semaphore = asyncio.Semaphore(concurrency)

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            tasks = [self._check_url(client, url, semaphore) for url in urls]
            results = await asyncio.gather(*tasks)
            # Use a set to deduplicate final URLs (e.g., if http and https both redirect to the same canonical URL)
            valid_urls = {url for url in results if url}

        logger.info(
            f"Validation complete: {len(valid_urls)}/{len(urls)} unique valid portals found."
        )
        return sorted(list(valid_urls))

    async def _check_url(
        self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore
    ) -> Optional[str]:
        """Checks if a URL is a valid Avature portal and follows redirects to the final destination."""
        async with semaphore:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    # Final landing page after redirects
                    final_url = str(response.url).rstrip("/")

                    # Log if it was a significant move
                    if final_url.lower() != url.lower().rstrip("/"):
                        logger.info(f"Redirect: {url} -> {final_url}")

                    # Check for Avature footprint
                    if "avature" in response.text.lower() or "avature" in str(
                        response.headers
                    ):
                        return final_url
                else:
                    logger.debug(f"Failed to validate {url}: {response.status_code}")
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        return None
