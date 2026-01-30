from urllib.parse import urlparse
import logging
import asyncio
from typing import Set, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import AsyncClient

logger = logging.getLogger(__name__)


class PortalDiscovery:
    """Discovers and normalizes Avature portal domains with public-only filtering."""

    BLACKLIST_KEYWORDS = (
        "sandbox",
        "training",
        "uat",
        "qa",
        "staging",
        "dev",
        "test-",
        "-test",
        "internal",
        "integrations",
        "mobiletrust",
        "api-",
        "preview",
        "demo-",
        "-demo",
        "portal-uat",
        "portal-stage",
    )

    # Domains to exclude - these are not actual job portals
    EXCLUDED_DOMAINS = (
        "www.avature.net",
        "avature.net",
    )

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
            netloc = parsed.netloc.lower()
            if "avature.net" in netloc:
                # Check blacklist keywords
                if any(k in netloc for k in PortalDiscovery.BLACKLIST_KEYWORDS):
                    return None
                # Check excluded domains (bare avature.net URLs)
                if netloc in PortalDiscovery.EXCLUDED_DOMAINS:
                    return None
                return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
        return None

    async def discover_from_ct_logs(self) -> Set[str]:
        """Query Certificate Transparency logs for *.avature.net using curl_cffi for better fingerprinting."""
        from curl_cffi.requests import AsyncSession

        logger.info("Querying Certificate Transparency logs for new portals...")
        domains = set()

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
                                    if not any(
                                        k in subname for k in self.BLACKLIST_KEYWORDS
                                    ):
                                        domains.add(f"https://{subname}")

                        logger.info(
                            f"CT logs successful: found {len(domains)} raw candidates."
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

    async def discover_from_wayback(self) -> Set[str]:
        """Query Wayback Machine CDX API for historical avature.net URLs."""
        from curl_cffi.requests import AsyncSession

        logger.info("Querying Wayback Machine CDX API for historical URLs...")
        domains = set()
        unique_seen = set()

        wayback_url = (
            "http://web.archive.org/cdx/search/cdx"
            "?url=avature.net&matchType=domain&fl=original&collapse=urlkey"
            "&output=txt&filter=mimetype:text/html"
        )

        try:
            async with AsyncSession(impersonate="chrome") as session:
                resp = await session.get(wayback_url, timeout=120)

                if resp.status_code == 200:
                    lines = resp.text.split("\n")
                    logger.info(
                        f"Wayback returned {len(lines)} historical URLs to process"
                    )

                    for line in lines:
                        raw_url = line.strip()
                        if not raw_url:
                            continue

                        if not raw_url.startswith("http"):
                            raw_url = "http://" + raw_url

                        try:
                            parsed = urlparse(raw_url)
                            domain = parsed.netloc.lower()

                            # Remove port if present
                            if ":" in domain:
                                domain = domain.split(":")[0]

                            # Check if it's a valid avature domain
                            if "avature.net" in domain and domain not in unique_seen:
                                unique_seen.add(domain)

                                # Apply blacklist and exclusion filters
                                if any(k in domain for k in self.BLACKLIST_KEYWORDS):
                                    continue
                                if domain in self.EXCLUDED_DOMAINS:
                                    continue

                                domains.add(f"https://{domain}")

                        except Exception:
                            pass

                    logger.info(f"Wayback found: {len(domains)} unique candidates.")
                else:
                    logger.warning(f"Wayback returned status {resp.status_code}")

        except Exception as e:
            logger.error(f"Wayback discovery failed: {e}")

        return domains

    async def discover_from_hackertarget(self) -> Set[str]:
        """Query HackerTarget API for DNS host records of avature.net subdomains."""
        from curl_cffi.requests import AsyncSession

        logger.info("Querying HackerTarget API for DNS records...")
        domains = set()

        try:
            async with AsyncSession(impersonate="chrome") as session:
                url = "https://api.hackertarget.com/hostsearch/?q=avature.net"
                resp = await session.get(url, timeout=20)

                if resp.status_code == 200:
                    lines = resp.text.split("\n")
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) > 0:
                            domain = parts[0].strip().lower()
                            if "avature.net" in domain:
                                if not any(
                                    k in domain for k in self.BLACKLIST_KEYWORDS
                                ):
                                    domains.add(f"https://{domain}")

                    logger.info(f"HackerTarget found: {len(domains)} candidates.")
                else:
                    logger.warning(f"HackerTarget returned status {resp.status_code}")

        except Exception as e:
            logger.error(f"HackerTarget discovery failed: {e}")

        return domains

    async def discover_from_alienvault(self) -> Set[str]:
        """Query AlienVault OTX passive DNS for avature.net subdomains."""
        from curl_cffi.requests import AsyncSession

        logger.info("Querying AlienVault OTX for passive DNS records...")
        domains = set()

        try:
            async with AsyncSession(impersonate="chrome") as session:
                url = "https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/avature.net"
                resp = await session.get(url, timeout=20)

                if resp.status_code == 200:
                    data = resp.json()
                    passive_dns = data.get("passive_dns", [])

                    for entry in passive_dns:
                        hostname = entry.get("hostname", "").lower()
                        if "avature.net" in hostname and "*" not in hostname:
                            if not any(k in hostname for k in self.BLACKLIST_KEYWORDS):
                                domains.add(f"https://{hostname}")

                    logger.info(f"AlienVault found: {len(domains)} candidates.")
                else:
                    logger.warning(f"AlienVault returned status {resp.status_code}")

        except Exception as e:
            logger.error(f"AlienVault discovery failed: {e}")

        return domains

    async def discover_from_urlscan(self) -> Set[str]:
        """Query Urlscan.io for vanity domains that redirect to or use Avature."""
        from curl_cffi.requests import AsyncSession
        from urllib.parse import urlparse as parse_url

        logger.info("Querying Urlscan.io for vanity domains...")
        domains = set()

        try:
            async with AsyncSession(impersonate="chrome") as session:
                url = "https://urlscan.io/api/v1/search/?q=domain:avature.net&size=1000"
                resp = await session.get(url, timeout=20)

                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])

                    for r in results:
                        task_url = r.get("task", {}).get("url", "")
                        if "avature.net" in task_url:
                            d = parse_url(task_url).netloc.lower()
                            if d and not any(k in d for k in self.BLACKLIST_KEYWORDS):
                                domains.add(f"https://{d}")

                    logger.info(f"Urlscan found: {len(domains)} candidates.")
                else:
                    logger.warning(f"Urlscan returned status {resp.status_code}")

        except Exception as e:
            logger.error(f"Urlscan discovery failed: {e}")

        return domains

    async def run_all_discovery(self) -> Set[str]:
        """Run all discovery methods in parallel and merge results."""
        logger.info("🚀 Starting Deep Recon for Avature Portals...")

        # Run all discovery methods concurrently
        ct_task = asyncio.create_task(self.discover_from_ct_logs())
        ht_task = asyncio.create_task(self.discover_from_hackertarget())
        av_task = asyncio.create_task(self.discover_from_alienvault())
        us_task = asyncio.create_task(self.discover_from_urlscan())
        wb_task = asyncio.create_task(self.discover_from_wayback())

        (
            ct_domains,
            ht_domains,
            av_domains,
            us_domains,
            wb_domains,
        ) = await asyncio.gather(ct_task, ht_task, av_task, us_task, wb_task)

        # Merge all domains
        all_domains = (
            ct_domains.union(ht_domains)
            .union(av_domains)
            .union(us_domains)
            .union(wb_domains)
        )

        logger.info(
            f"Discovery complete: CT={len(ct_domains)}, HackerTarget={len(ht_domains)}, "
            f"AlienVault={len(av_domains)}, Urlscan={len(us_domains)}, Wayback={len(wb_domains)} "
            f"-> Total unique: {len(all_domains)}"
        )

        return all_domains

    async def validate_portals(
        self, urls: List[str], concurrency: int = 10
    ) -> List[str]:
        """Validates portals in parallel to ensure they are active public Avature sites."""
        from .client import AsyncClient

        logger.info(f"Validating {len(urls)} portals with concurrency={concurrency}...")
        semaphore = asyncio.Semaphore(concurrency)

        client = AsyncClient(timeout=15, max_connections=concurrency + 5)
        try:
            tasks = [self._check_url(client, url, semaphore) for url in urls]
            results = await asyncio.gather(*tasks)
            valid_urls = {url for url in results if url}
        finally:
            await client.close()

        logger.info(
            f"Validation complete: {len(valid_urls)}/{len(urls)} unique public portals found."
        )
        return sorted(list(valid_urls))

    async def _check_url(
        self, client: "AsyncClient", url: str, semaphore: asyncio.Semaphore
    ) -> Optional[str]:
        """Checks if a URL is a valid public Avature career portal by checking base and /careers path."""
        async with semaphore:
            # We try the base URL first, then /careers if the base doesn't look like a portal
            paths_to_try = ["", "/careers"]

            for path in paths_to_try:
                try:
                    target_url = url.rstrip("/") + path
                    response = await client.get(target_url, timeout=10)

                    if response.status_code == 200:
                        html = response.text.lower()
                        final_url = str(response.url).rstrip("/")

                        # Check for general Avature footprint
                        is_avature = (
                            "avature" in html
                            or "avature" in str(response.headers).lower()
                        )

                        if not is_avature:
                            continue

                        # Filter out internal/noindex pages
                        if (
                            'content="noindex"' in html
                            or 'name="robots" content="none"' in html
                        ):
                            continue

                        # Check for public signatures
                        # Broaden signatures to catch more portals
                        public_sigs = [
                            "job search",
                            "career",
                            "search jobs",
                            "view all jobs",
                            "talent community",
                            "opportunities",
                            "positions",
                            "jobdetail",
                            "portal",
                            "employment",
                        ]
                        is_public = any(sig in html for sig in public_sigs)

                        # Special case: If the page has a JS redirect to /Login/ on the SAME domain, it's likely internal
                        if "window.location.href" in html and "/login/" in html:
                            # If we are at the base and it redirects to login, it might be internal
                            # but we'll still let it pass for /careers if that works
                            if path == "" and "/careers" not in html:
                                continue

                        if is_avature and (is_public or path == "/careers"):
                            if final_url.lower() != url.lower().rstrip("/"):
                                logger.info(f"Detected: {url} -> {final_url}")
                            return final_url

                except Exception as e:
                    logger.debug(f"Error checking {url}{path}: {e}")

        return None
