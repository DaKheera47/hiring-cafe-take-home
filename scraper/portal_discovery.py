from urllib.parse import urlparse
import logging
from typing import Set, Optional
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

    @staticmethod
    async def discover_from_ct_logs() -> Set[str]:
        """Query Certificate Transparency logs for *.avature.net."""
        logger.info("Querying Certificate Transparency logs for new portals...")
        domains = set()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get("https://crt.sh/?q=%.avature.net&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "").lower()
                        for subname in name.split("\n"):
                            if subname.startswith("*."):
                                subname = subname[2:]
                            if subname.endswith(".avature.net"):
                                domains.add(f"https://{subname}")
        except Exception as e:
            logger.error(f"CT log discovery failed: {e}")

        return domains
