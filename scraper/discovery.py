import re
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse
from .client import AsyncClient

logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Discovers jobs via Sitemaps and patterns found in Avature portals."""

    def __init__(self, client: AsyncClient):
        self.client = client

    async def find_job_urls_from_sitemap(self, domain_url: str) -> Set[str]:
        """Harvests job URLs using the robust tag-stripping method."""
        sitemap_urls = await self._get_sitemap_urls(domain_url)
        job_urls = set()

        for s_url in sitemap_urls:
            resp = await self.client.get(s_url)
            if not resp or not resp.text:
                continue

            content = resp.text

            # Implementation of your logic:
            # 1. Strip all XML tags to get raw text content
            clean_text = re.sub(r"<[^>]+>", " ", content)

            # 2. Add newlines before https to separate concatenated entries
            processed_content = clean_text.replace("https:", "\nhttps:")
            processed_content = processed_content.replace(
                "http:", "\nhttp:"
            )  # Support http too

            # 3. Process each potential URL line
            lines = processed_content.splitlines()
            for line in lines:
                parts = (
                    line.strip().split()
                )  # Split by whitespace in case multiple tags were stripped
                for part in parts:
                    if "JobDetail" in part and part.startswith("http"):
                        # Extract the URL. If it has a date at the end (User logic), strip it.
                        # Avature sitemaps often have the date immediately following the URL in stripped text.
                        # URL looks like: https.../JobDetail/123452026-01-13
                        match = re.search(r"(https?://.*?/JobDetail/\d+)", part)
                        if match:
                            job_urls.add(match.group(1))
                        else:
                            # Fallback to simple strip if the numeric ID + Date is messy
                            # Just take the part that contains JobDetail
                            job_urls.add(part)

            # If we didn't find anything with the strip method, try one more regex fallback
            if not job_urls:
                job_urls.update(
                    re.findall(r"https?://[^<\s]+JobDetail/[^<\s]+", content)
                )

        if job_urls:
            logger.info(
                f"Successfully harvested {len(job_urls)} jobs from {domain_url}"
            )

        return job_urls

    async def _get_sitemap_urls(self, domain_url: str) -> List[str]:
        """Exhaustive check for Avature sitemap locations."""
        base = f"{urlparse(domain_url).scheme}://{urlparse(domain_url).netloc}"

        # We try these specific Avature paths which are often hidden from robots.txt
        paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/careers/sitemap.xml",
            "/careers/sitemap_index.xml",
            "/en_US/careers/sitemap.xml",
        ]

        found_sitemaps = []

        # First check robots.txt for explicit paths
        robots_url = urljoin(base, "/robots.txt")
        resp = await self.client.get(robots_url)
        if resp and resp.status_code == 200:
            sitemaps = re.findall(r"^Sitemap: (.*)$", resp.text, re.MULTILINE)
            for s in sitemaps:
                found_sitemaps.append(s.strip())

        # Always add the common Avature sitemap paths as candidates
        for p in paths:
            if not p.endswith("robots.txt"):
                found_sitemaps.append(urljoin(base, p))

        return list(set(found_sitemaps))  # Deduplicate
