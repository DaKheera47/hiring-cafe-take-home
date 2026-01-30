from bs4 import BeautifulSoup
import extruct
from typing import Optional, Dict, Any, List
import json
import re
from .models import JobEntry


class JobParser:
    """Intelligent parser prioritizing structured schema data (JSON-LD)."""

    @staticmethod
    def extract_from_html(html: str, url: str, base_company: str) -> Optional[JobEntry]:
        soup = BeautifulSoup(html, "lxml")

        # 1. Try JSON-LD (The gold standard)
        try:
            data = extruct.extract(html, base_url=url, syntaxes=["json-ld"])
            for item in data.get("json-ld", []):
                if item.get("@type") == "JobPosting" or "JobPosting" in str(
                    item.get("@type")
                ):
                    return JobParser._map_schema_to_model(item, url, base_company)
        except Exception:
            pass

        # 2. Fallback to BeautifulSoup logic
        return JobParser._fallback_parse(soup, url, base_company)

    @staticmethod
    def _map_schema_to_model(
        schema: Dict[str, Any], url: str, company: str
    ) -> JobEntry:
        return JobEntry(
            title=schema.get("title", "Unknown Title"),
            company=company,
            location=JobParser._parse_location(schema.get("jobLocation")),
            description=schema.get("description"),
            application_url=url,
            job_id=schema.get("identifier", {}).get("value")
            if isinstance(schema.get("identifier"), dict)
            else str(schema.get("identifier")),
            date_posted=schema.get("datePosted"),
            employment_type=schema.get("employmentType"),
            metadata=schema,
        )

    @staticmethod
    def _parse_location(loc: Any) -> str:
        if not loc:
            return "Remote"
        if isinstance(loc, str):
            return loc
        if isinstance(loc, dict):
            addr = loc.get("address", {})
            if isinstance(addr, dict):
                parts = [
                    addr.get("addressLocality"),
                    addr.get("addressRegion"),
                    addr.get("addressCountry"),
                ]
                return ", ".join([p for p in parts if p])
        return "Unknown"

    @staticmethod
    def _fallback_parse(
        soup: BeautifulSoup, url: str, company: str
    ) -> Optional[JobEntry]:
        # Simple heuristic fallback
        title_tag = soup.find("h1") or soup.find("title")
        if not title_tag:
            return None

        return JobEntry(
            title=title_tag.text.strip(), company=company, application_url=url
        )
