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
        """
        import requests
        from requests.adapters import HTTPAdapter
        import threading
        import queue
        from rich.progress import (
            Progress,
            SpinnerColumn,
            TextColumn,
            BarColumn,
            TaskProgressColumn,
            TimeRemainingColumn,
            MofNCompleteColumn,
        )

        # Silence noisy urllib3 logs during firehose
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("requests").setLevel(logging.ERROR)

        try:
            from urllib3.util.retry import Retry
        except Exception:
            Retry = None

        # Configs
        WORKER_THREADS = 30
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

        def build_session(retries=True) -> requests.Session:
            s = requests.Session()
            if retries and Retry is not None:
                retry = Retry(
                    total=5,
                    connect=5,
                    read=5,
                    backoff_factor=1.0,
                    status_forcelist=(429, 500, 502, 503, 504),
                    raise_on_status=False,
                )
                adapter = HTTPAdapter(
                    max_retries=retry,
                    pool_connections=WORKER_THREADS + 10,
                    pool_maxsize=WORKER_THREADS + 10,
                )
                s.mount("https://", adapter)
                s.mount("http://", adapter)
            else:
                # Minimal adapter for validation (no retries)
                adapter = HTTPAdapter(
                    pool_connections=WORKER_THREADS + 10,
                    pool_maxsize=WORKER_THREADS + 10,
                )
                s.mount("https://", adapter)
                s.mount("http://", adapter)
            return s

        # Separate sessions: one for the stable stream, one for the chaotic domain checks
        wayback_session = build_session(retries=True)
        validation_session = build_session(retries=False)

        wayback_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; avature-scraper/1.0; +https://hiring.cafe)",
            "Accept": "text/plain,*/*",
        }

        wayback_url = "https://web.archive.org/web/timemap/cdx?url=avature.net&matchType=domain&fl=original&collapse=urlkey"

        seen_domains: Set[str] = set()
        validated_domains: Set[str] = set()
        domain_queue: queue.Queue = queue.Queue(maxsize=1000)
        stop_event = threading.Event()
        producer_done = threading.Event()
        lock = threading.Lock()

        def validate_domain(domain: str) -> Optional[str]:
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36"
            }
            url = f"https://{domain}/careers"
            try:
                # Quick probe
                r = validation_session.head(
                    url, headers=headers, timeout=(5, 10), allow_redirects=True
                )
                if r.status_code in (405, 403):
                    r = validation_session.get(
                        url,
                        headers=headers,
                        timeout=(5, 10),
                        allow_redirects=True,
                        stream=True,
                    )

                if r.status_code == 200:
                    if r.request.method != "GET":
                        r = validation_session.get(
                            url,
                            headers=headers,
                            timeout=(5, 10),
                            allow_redirects=True,
                            stream=True,
                        )

                    # Sig check
                    chunk = b""
                    try:
                        for part in r.iter_content(chunk_size=4096):
                            chunk = part
                            break
                    except:
                        pass

                    body_l = chunk.decode("utf-8", "ignore").lower()
                    headers_l = str(r.headers).lower()

                    if "avature" in body_l or "avature" in headers_l:
                        return f"https://{domain}"

                elif r.status_code == 406:
                    return f"https://{domain}"
            except:
                pass
            return None

        # --- Progress Logic ---
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            refresh_per_second=4,
        ) as progress:
            # We don't know the exact total for wayback, but we can guess based on history or use total=0
            stream_task = progress.add_task(
                "[cyan]🌊 Streaming Wayback CDX...", total=None
            )
            validation_task = progress.add_task(
                "[green]🛡️ Validating Portals...", total=None
            )

            def validation_worker():
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
                        progress.advance(validation_task)
                        domain_queue.task_done()

            def stream_wayback():
                count = 0
                for attempt in range(1, 4):
                    if stop_event.is_set():
                        break
                    try:
                        with wayback_session.get(
                            wayback_url,
                            stream=True,
                            headers=wayback_headers,
                            timeout=(15, 300),
                        ) as r:
                            if r.status_code != 200:
                                import time

                                time.sleep(5)
                                continue

                            for line in r.iter_lines(
                                chunk_size=65536, decode_unicode=True
                            ):
                                if stop_event.is_set():
                                    break
                                if not line:
                                    continue

                                raw_url = line.strip()
                                if (
                                    raw_url.lower().endswith(JUNK_EXTS)
                                    or "/portal/t9/" in raw_url.lower()
                                ):
                                    continue

                                try:
                                    domain = (
                                        urlparse(
                                            raw_url
                                            if "://" in raw_url
                                            else f"http://{raw_url}"
                                        )
                                        .netloc.lower()
                                        .split(":")[0]
                                    )
                                    if (
                                        "avature.net" not in domain
                                        or domain in seen_domains
                                    ):
                                        continue

                                    seen_domains.add(domain)
                                    if (
                                        any(
                                            k in domain for k in self.BLACKLIST_KEYWORDS
                                        )
                                        or domain in self.EXCLUDED_DOMAINS
                                    ):
                                        continue

                                    domain_queue.put(domain)
                                    count += 1

                                    progress.update(
                                        stream_task,
                                        description=f"[cyan]🌊 Streamed: {count} domains",
                                    )
                                    # Dynamically update validation total
                                    progress.update(validation_task, total=count)

                                except:
                                    pass
                        break
                    except Exception as e:
                        import time

                        time.sleep(5)

                producer_done.set()
                progress.update(
                    stream_task,
                    description="[cyan]✅ Stream Complete",
                    completed=1,
                    total=1,
                )

            # Execution
            workers = [
                threading.Thread(target=validation_worker, daemon=True)
                for _ in range(WORKER_THREADS)
            ]
            for w in workers:
                w.start()

            producer_thread = threading.Thread(target=stream_wayback, daemon=True)
            producer_thread.start()

            try:
                producer_thread.join()
                domain_queue.join()
            except KeyboardInterrupt:
                stop_event.set()
                producer_done.set()

        logger.info(
            f"✨ Wayback Discovery Finalized: {len(validated_domains)} active portals."
        )
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
        from rich.progress import (
            Progress,
            SpinnerColumn,
            TextColumn,
            BarColumn,
            TaskProgressColumn,
            MofNCompleteColumn,
            TimeRemainingColumn,
        )

        logger.info(f"Validating {len(urls)} portals with concurrency={concurrency}...")
        semaphore = asyncio.Semaphore(concurrency)

        client = AsyncClient(timeout=15, max_connections=concurrency + 5)
        valid_urls = set()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                refresh_per_second=4,
            ) as progress:
                task = progress.add_task(
                    "[green]🛡️  Validating Portals...", total=len(urls)
                )

                async def _checked_task(url):
                    try:
                        res = await self._check_url(client, url, semaphore)
                        return res
                    finally:
                        progress.advance(task)

                tasks = [_checked_task(url) for url in urls]
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
                    response = await client.get(
                        target_url, timeout=10, max_retries=0, base_delay=5.0
                    )

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
