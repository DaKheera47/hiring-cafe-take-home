"""
WAF Bypass Engine for Avature ATS Scraping
===========================================
Production-grade TLS client with strict browser persona enforcement.

Key Anti-Detection Features:
1. Strict Firefox 117 TLS fingerprint (JA3 matching)
2. HTTP/2 compliant headers (no Connection/Host headers)
3. Domain-aware session caching with handshake logic
4. Cookie persistence for ScustomPortal-{ID} tokens
"""

import asyncio
import logging
from typing import Dict, Optional
from urllib.parse import urlparse

import tls_client

logger = logging.getLogger(__name__)

# === CRITICAL: Firefox 117 Browser Persona ===
# The TLS Client Hello *must* match the User-Agent exactly.
# Any mismatch triggers JA3 fingerprint detection.
FIREFOX_117_CLIENT_ID = "firefox_117"

# Exact Firefox 117 on Windows User-Agent (must match TLS fingerprint)
FIREFOX_117_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0"
)


def get_firefox_117_headers(referer: Optional[str] = None) -> Dict[str, str]:
    """
    Returns HTTP headers that exactly match Firefox 117's fingerprint.

    CRITICAL RULES:
    - Headers MUST be in correct browser order
    - NO 'Connection' header (HTTP/2 violation)
    - NO 'Host' header (HTTP/2 uses :authority pseudo-header)
    - Accept-Language is consistent (not randomized)
    """
    headers = {
        # === Required headers in Firefox order ===
        "User-Agent": FIREFOX_117_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        # === Firefox-specific headers ===
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",  # First navigation is "none"
        "Sec-Fetch-User": "?1",
    }

    # Add referer for subsequent requests (cross-site navigation)
    if referer:
        headers["Referer"] = referer
        headers["Sec-Fetch-Site"] = "same-origin"

    return headers


class SessionManager:
    """
    Domain-aware session cache with handshake logic.

    The "Handshake" Pattern:
    1. Before accessing /JobDetail/123, check if we have a session for that domain
    2. If NO session: Create new Firefox session, hit the careers homepage first
       to capture ScustomPortal-{ID} cookies, then cache the session
    3. If YES session: Reuse it (cookies pass automatically)

    This mimics legitimate user browsing and passes WAF behavioral analysis.
    """

    def __init__(self):
        self._sessions: Dict[str, tls_client.Session] = {}
        self._lock = asyncio.Lock()

    def _create_firefox_session(self) -> tls_client.Session:
        """Creates a new TLS session with strict Firefox 117 fingerprint."""
        return tls_client.Session(
            client_identifier=FIREFOX_117_CLIENT_ID,
            random_tls_extension_order=False,  # Consistent fingerprint
        )

    def _extract_domain(self, url: str) -> str:
        """Extracts the domain (netloc) from a URL."""
        return urlparse(url).netloc

    def _get_base_url(self, url: str) -> str:
        """Gets the base URL (scheme + netloc) from a URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def get_session(self, url: str) -> tls_client.Session:
        """
        Returns a cached session for the domain, or creates one with handshake.

        The handshake hits /careers first to capture portal cookies.
        """
        domain = self._extract_domain(url)

        async with self._lock:
            if domain not in self._sessions:
                logger.debug(f"Creating new Firefox 117 session for {domain}")
                session = self._create_firefox_session()
                self._sessions[domain] = session

                # === HANDSHAKE: Visit careers page first to get cookies ===
                base_url = self._get_base_url(url)
                careers_url = f"{base_url}/careers"

                try:
                    logger.debug(
                        f"Handshake: Visiting {careers_url} to capture cookies"
                    )
                    headers = get_firefox_117_headers()

                    # This is sync, run in thread
                    await asyncio.to_thread(
                        session.get,
                        careers_url,
                        headers=headers,
                        timeout_seconds=30,
                        allow_redirects=True,
                    )
                    logger.debug(f"Handshake complete for {domain}")
                except Exception as e:
                    logger.warning(f"Handshake failed for {domain}: {e}")
                    # Continue anyway - session is still usable

            return self._sessions[domain]

    async def invalidate_session(self, url: str) -> None:
        """Removes a session from cache (call after repeated failures)."""
        domain = self._extract_domain(url)
        async with self._lock:
            if domain in self._sessions:
                del self._sessions[domain]
                logger.debug(f"Invalidated session for {domain}")

    def clear_all(self) -> None:
        """Clears all cached sessions."""
        self._sessions.clear()


class AsyncClient:
    """
    Async wrapper for tls-client with WAF bypass capabilities.

    Key Features:
    - Strict Firefox 117 TLS fingerprint enforcement
    - HTTP/2 compliant (no illegal headers)
    - Domain-aware session caching with handshake
    - Exponential backoff with session rotation on blocks
    """

    def __init__(self, timeout: int = 30, max_connections: int = 100):
        self.timeout = timeout
        self.max_connections = max_connections
        self._session_manager = SessionManager()

    async def get(
        self, url: str, max_retries: int = 4, **kwargs
    ) -> Optional[tls_client.response.Response]:
        """
        Fetches a URL with automatic retries for rate-limiting (403, 406, 429).

        Uses domain-cached sessions and Firefox 117 fingerprint.
        """
        base_delay = 30.0  # Base delay before exponential backoff
        base_url = urlparse(url)
        referer = f"{base_url.scheme}://{base_url.netloc}/careers"

        for attempt in range(max_retries + 1):
            # Small jitter between requests to look human
            await asyncio.sleep(1.0 + (attempt * 0.5))

            try:
                # Get domain-cached session (with handshake if needed)
                session = await self._session_manager.get_session(url)

                # Firefox 117 headers (HTTP/2 compliant - no Connection/Host)
                headers = get_firefox_117_headers(
                    referer=referer if attempt > 0 else None
                )

                # Merge any custom headers (but never override critical ones)
                if "headers" in kwargs:
                    custom = kwargs.pop("headers")
                    # Only merge non-critical headers
                    for k, v in custom.items():
                        if k.lower() not in ("user-agent", "connection", "host"):
                            headers[k] = v

                # Handle timeout
                timeout_val = kwargs.pop("timeout", self.timeout)
                if isinstance(timeout_val, (int, float)):
                    timeout_seconds = int(timeout_val)
                else:
                    timeout_seconds = (
                        getattr(timeout_val, "connect", self.timeout) or self.timeout
                    )

                # tls-client is sync, run in thread
                response = await asyncio.to_thread(
                    session.get,
                    url,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                    allow_redirects=kwargs.pop("follow_redirects", True),
                    **kwargs,
                )

                if response.status_code == 200:
                    return response

                if response.status_code == 404:
                    return None

                # === WAF Block Detection ===
                if response.status_code in (403, 406, 429):
                    domain = urlparse(url).netloc

                    if attempt < max_retries:
                        # Exponential backoff with jitter
                        sleep_time = base_delay * (2**attempt) + (attempt * 2)

                        logger.warning(
                            f"WAF Block ({response.status_code}) on {domain}. "
                            f"Rotating session and retrying in {sleep_time:.1f}s "
                            f"(Attempt {attempt + 1}/{max_retries})"
                        )

                        # Invalidate the blocked session and create fresh one
                        await self._session_manager.invalidate_session(url)

                        await asyncio.sleep(sleep_time)
                        continue
                    else:
                        logger.error(
                            f"Failed to fetch {domain} after {max_retries} retries "
                            f"(final status: {response.status_code})"
                        )
                        return None

                # Other status codes - log and return None
                logger.warning(f"Unexpected status {response.status_code} for {url}")
                return None

            except Exception as e:
                domain = urlparse(url).netloc

                if attempt < max_retries:
                    sleep_time = base_delay * (2**attempt)
                    logger.warning(
                        f"Request error for {domain}: {e}. Retrying in {sleep_time:.1f}s"
                    )
                    await asyncio.sleep(sleep_time)
                    continue

                logger.error(
                    f"Error fetching {domain} after {max_retries} retries: {e}"
                )
                return None

        return None

    async def close(self) -> None:
        """Clears all cached sessions."""
        self._session_manager.clear_all()
