import re
from typing import List, Set
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from .client import AsyncClient


class DiscoveryEngine:
    """Discovers jobs via Sitemaps and API endpoints."""

    def __init__(self, client: AsyncClient):
        self.client = client

    async def find_job_urls_from_sitemap(self, domain_url: str) -> Set[str]:
        """The 'Secret Sauce': Harvesting jobs via XML sitemaps."""
        sitemap_urls = await self._get_sitemap_urls(domain_url)
        job_urls = set()

        for s_url in sitemap_urls:
            resp = await self.client.get(s_url)
            if not resp:
                continue

            try:
                # Handle Sitemap Index files
                if "sitemapindex" in resp.text:
                    sub_sitemaps = re.findall(r"<loc>(.*?)</loc>", resp.text)
                    for sub_s in sub_sitemaps:
                        if (
                            "job" in sub_s.lower()
                            or "career" in sub_s.lower()
                            or "sitemap" in sub_s
                        ):
                            sub_resp = await self.client.get(sub_s)
                            if sub_resp:
                                job_urls.update(
                                    re.findall(
                                        r"<loc>(.*?/JobDetail/.*?)</loc>", sub_resp.text
                                    )
                                )
                else:
                    # Regular sitemap
                    job_urls.update(
                        re.findall(r"<loc>(.*?/JobDetail/.*?)</loc>", resp.text)
                    )
            except Exception:
                continue

        return job_urls

    async def _get_sitemap_urls(self, domain_url: str) -> List[str]:
        """Check robots.txt and common locations."""
        base = f"{urlparse(domain_url).scheme}://{urlparse(domain_url).netloc}"

        # 1. Check robots.txt
        robots_url = urljoin(base, "/robots.txt")
        resp = await self.client.get(robots_url)
        if resp:
            sitemaps = re.findall(r"^Sitemap: (.*)$", resp.text, re.MULTILINE)
            if sitemaps:
                return sitemaps

        # 2. Heuristic fallback
        return [
            urljoin(base, "/sitemap.xml"),
            urljoin(base, "/careers/sitemap_index.xml"),
            urljoin(base, "/careers/sitemap.xml"),
        ]
