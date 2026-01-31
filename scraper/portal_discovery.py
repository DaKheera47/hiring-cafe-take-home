from urllib.parse import urlparse
import logging
import asyncio
from typing import Set, Optional, List, Dict, Tuple, TYPE_CHECKING

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
        """
        Query Wayback Machine CDX API with streaming and concurrent validation.

        This implements the "firehose" pattern:
        1. Stream CDX results with retry logic
        2. Filter junk extensions client-side
        3. Deduplicate domains on-the-fly
        4. Validate discovered domains with HEAD/GET requests
        5. Check for Avature signature in response
        """
        import requests
        from requests.adapters import HTTPAdapter
        import threading
        import queue

        try:
            from urllib3.util.retry import Retry
        except Exception:
            Retry = None

        logger.info("🌊 Starting Wayback Machine firehose discovery...")

        # Junk extensions to filter out
        JUNK_EXTS = (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".json",
            ".xml",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".map",
            ".pdf",
        )

        # Build session with retry logic
        def build_session() -> requests.Session:
            s = requests.Session()
            if Retry is not None:
                retry = Retry(
                    total=5,
                    connect=5,
                    read=5,
                    backoff_factor=1.0,
                    status_forcelist=(429, 500, 502, 503, 504),
                )
                adapter = HTTPAdapter(
                    max_retries=retry, pool_connections=50, pool_maxsize=50
                )
                s.mount("https://", adapter)
                s.mount("http://", adapter)
            return s

        session = build_session()

        wayback_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; avature-scraper/1.0; +https://example.invalid)",
            "Accept": "text/plain,*/*",
        }

        # Use the timemap CDX endpoint for better streaming
        wayback_url = (
            "https://web.archive.org/web/timemap/cdx"
            "?url=avature.net&matchType=domain&fl=original&collapse=urlkey"
        )

        seen_domains: Set[str] = set()
        validated_domains: Set[str] = set()
        domain_queue: queue.Queue = queue.Queue(maxsize=1000)
        stop_event = threading.Event()
        producer_done = threading.Event()
        lock = threading.Lock()

        def validate_domain(domain: str) -> Optional[str]:
            """Validate a single domain with HEAD/GET and signature check."""
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36"
            }
            url = f"https://{domain}/careers"

            try:
                # HEAD for cheap existence/redirect check
                r = session.head(
                    url, headers=headers, timeout=(10, 20), allow_redirects=True
                )

                # GET fallback if HEAD is blocked
                if r.status_code in (405, 403):
                    r = session.get(
                        url,
                        headers=headers,
                        timeout=(10, 30),
                        allow_redirects=True,
                        stream=True,
                    )

                if r.status_code == 200:
                    # Do a GET if we only did HEAD
                    if r.request.method != "GET":
                        r = session.get(
                            url,
                            headers=headers,
                            timeout=(10, 30),
                            allow_redirects=True,
                            stream=True,
                        )

                    # Read only a small chunk for signature
                    chunk = b""
                    try:
                        for part in r.iter_content(chunk_size=32768):
                            chunk = part
                            break
                    except Exception:
                        chunk = b""

                    body_l = chunk.decode("utf-8", "ignore").lower()
                    headers_l = str(r.headers).lower()

                    if ("avature" in body_l) or ("avature" in headers_l):
                        logger.debug(f"✅ Validated: {domain}")
                        return f"https://{domain}"

                elif r.status_code == 406:
                    # 406 means the server exists but is hostile to our probe
                    # We treat this as valid (it's an Avature WAF)
                    logger.debug(f"⚠️ 406 (WAF): {domain}")
                    return f"https://{domain}"

            except Exception as e:
                logger.debug(f"Validation error for {domain}: {e}")

            return None

        def validation_worker():
            """Worker thread that validates domains from the queue."""
            while not stop_event.is_set():
                try:
                    domain = domain_queue.get(timeout=1)
                except queue.Empty:
                    if producer_done.is_set():
                        return
                    continue

                try:
                    result = validate_domain(domain)
                    if result:
                        with lock:
                            validated_domains.add(result)
                finally:
                    domain_queue.task_done()

        def stream_wayback():
            """Stream CDX results with retry logic."""
            count = 0

            for attempt in range(1, 6):
                if stop_event.is_set():
                    break

                try:
                    logger.info(f"Wayback stream attempt {attempt}/5...")
                    with session.get(
                        wayback_url,
                        stream=True,
                        headers=wayback_headers,
                        timeout=(15, 180),
                    ) as r:
                        if r.status_code != 200:
                            logger.warning(f"Wayback returned {r.status_code}")
                            import time

                            time.sleep(min(2**attempt, 30))
                            continue

                        for line in r.iter_lines(chunk_size=65536, decode_unicode=True):
                            if stop_event.is_set():
                                break
                            if not line:
                                continue

                            raw_url = line.strip()
                            lower_url = raw_url.lower()

                            # Client-side filter
                            if (
                                lower_url.endswith(JUNK_EXTS)
                                or "/portal/t9/" in lower_url
                            ):
                                continue

                            if not raw_url.startswith("http"):
                                raw_url = "http://" + raw_url

                            try:
                                parsed = urlparse(raw_url)
                                domain = parsed.netloc.lower()

                                # Remove port if present
                                if ":" in domain:
                                    domain = domain.split(":")[0]

                                if "avature.net" not in domain:
                                    continue

                                # Dedup and filter
                                if domain in seen_domains:
                                    continue
                                seen_domains.add(domain)

                                # Apply blacklist
                                if any(k in domain for k in self.BLACKLIST_KEYWORDS):
                                    continue
                                if domain in self.EXCLUDED_DOMAINS:
                                    continue

                                # Queue for validation
                                domain_queue.put(domain)
                                count += 1

                                if count % 50 == 0:
                                    logger.info(
                                        f"🌊 Streamed: {count} | Queued: {domain_queue.qsize()} | "
                                        f"Validated: {len(validated_domains)}"
                                    )

                            except Exception:
                                pass

                    # If we completed without exception, stop retrying
                    logger.info(
                        f"✅ Wayback stream complete: {count} unique domains found"
                    )
                    break

                except Exception as e:
                    logger.warning(f"Wayback stream error (attempt {attempt}/5): {e}")
                    import time

                    time.sleep(min(2**attempt, 30))
                    continue

            producer_done.set()

        # Run the streaming + validation in threads
        WORKER_THREADS = 20
        workers = []

        # Start validation workers
        for _ in range(WORKER_THREADS):
            t = threading.Thread(target=validation_worker, daemon=True)
            t.start()
            workers.append(t)

        # Run producer in a separate thread
        producer_thread = threading.Thread(target=stream_wayback)
        producer_thread.start()

        try:
            producer_thread.join()
            domain_queue.join()
        except KeyboardInterrupt:
            logger.warning("Wayback discovery interrupted")
            stop_event.set()
            producer_done.set()

        logger.info(f"🎉 Wayback validated: {len(validated_domains)} active portals")
        return validated_domains

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

    async def run_all_discovery(self) -> Tuple[Set[str], Dict[str, int]]:
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

        stats = {
            "CT Logs": len(ct_domains),
            "HackerTarget": len(ht_domains),
            "AlienVault": len(av_domains),
            "Urlscan.io": len(us_domains),
            "Wayback Machine": len(wb_domains),
        }

        logger.info(
            f"Discovery complete: CT={len(ct_domains)}, HackerTarget={len(ht_domains)}, "
            f"AlienVault={len(av_domains)}, Urlscan={len(us_domains)}, Wayback={len(wb_domains)} "
            f"-> Total unique: {len(all_domains)}"
        )

        return all_domains, stats

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
