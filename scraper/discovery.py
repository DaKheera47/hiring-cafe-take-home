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
            resp = await self.client.get(s_url, max_retries=1, base_delay=5.0)
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
                parts = line.strip().split()
                for part in parts:
                    # Clean trailing slashes or junk
                    part = part.strip().rstrip(" /")

                    if "JobDetail" in part and part.startswith("http"):
                        # 1. Skip obvious generic landing pages (uop.avature.net/careers/JobDetail)
                        # or internal job landing templates (../InJobDetail)
                        if part.lower().endswith("/jobdetail") or part.lower().endswith(
                            "/injobdetail"
                        ):
                            continue

                        # 2. Extract specific job URL (stripping trailing concatenated text/dates)
                        # We look for a pattern that has something AFTER the JobDetail part
                        # Standard ID-only: .../JobDetail/12345
                        # Slug+ID: .../JobDetail/Title-Slug/12345
                        match = re.search(
                            r"(https?://.*?/JobDetail/.*?/\d+)", part, re.IGNORECASE
                        )
                        if match:
                            job_urls.add(match.group(1))
                        elif re.search(
                            r"(https?://.*?/JobDetail/\d+)", part, re.IGNORECASE
                        ):
                            job_urls.add(
                                re.search(
                                    r"(https?://.*?/JobDetail/\d+)", part, re.IGNORECASE
                                ).group(1)
                            )
                        elif "/JobDetail/" in part and not part.endswith("/JobDetail"):
                            # Last safeguard: if it looks like a job URL but doesn't fit the ID-at-end pattern
                            job_urls.add(part)

            # If we didn't find anything with the strip method, try one more regex fallback
            if not job_urls:
                raw_found = re.findall(
                    r"https?://[^<\s]+JobDetail/[^<\s]+", content, re.IGNORECASE
                )
                for r in raw_found:
                    r = r.rstrip(" /")
                    if not (
                        r.lower().endswith("/jobdetail")
                        or r.lower().endswith("/injobdetail")
                    ):
                        job_urls.add(r)

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
        resp = await self.client.get(robots_url, max_retries=1, base_delay=5.0)
        if resp and resp.status_code == 200:
            sitemaps = re.findall(r"^Sitemap: (.*)$", resp.text, re.MULTILINE)
            for s in sitemaps:
                found_sitemaps.append(s.strip())

        # Always add the common Avature sitemap paths as candidates
        for p in paths:
            if not p.endswith("robots.txt"):
                found_sitemaps.append(urljoin(base, p))

        return list(set(found_sitemaps))  # Deduplicate
