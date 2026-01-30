from bs4 import BeautifulSoup
import json
import logging
from typing import Optional, Dict, Any
from .models import JobEntry

logger = logging.getLogger(__name__)


class JobParser:
    """Universal Avature Scraper with multi-strategy fallbacks."""

    @staticmethod
    def extract_from_html(html: str, url: str, base_company: str) -> Optional[JobEntry]:
        soup = BeautifulSoup(html, "html.parser")

        # Strategy 1: JSON-LD (Best Quality)
        json_data = JobParser._extract_json_ld(soup)
        if json_data:
            return JobParser._to_job_entry(
                json_data, url, base_company, strategy="json_ld"
            )

        # Strategy 2: Avature Generic CSS (Medium Quality)
        css_data = JobParser._extract_avature_css(soup)
        if css_data and (css_data.get("title") or css_data.get("page_title")):
            return JobParser._to_job_entry(
                css_data, url, base_company, strategy="avature_css"
            )

        # Strategy 3: Meta Tags (Fallback)
        meta_data = JobParser._extract_meta_tags(soup)
        if meta_data and meta_data.get("title"):
            return JobParser._to_job_entry(
                meta_data, url, base_company, strategy="meta_tags"
            )

        return None

    @staticmethod
    def _extract_json_ld(soup: BeautifulSoup) -> Optional[Dict[str, Any]]:
        """Finds Google Jobs structured data."""
        scripts = soup.find_all("script", type="application/ld+json")
        for script in scripts:
            try:
                # Some scripts might contain multiple items or be wrapped in CDATA
                text = script.string
                if not text:
                    continue

                data = json.loads(text)
                if isinstance(data, list):
                    data = data[0]

                if data.get("@type") == "JobPosting":
                    return {
                        "title": data.get("title"),
                        "company": data.get("hiringOrganization", {}).get("name"),
                        "location": JobParser._parse_schema_location(
                            data.get("jobLocation")
                        ),
                        "description": data.get("description"),
                        "date_posted": data.get("datePosted"),
                        "job_id": str(data.get("identifier", {}).get("value", ""))
                        if isinstance(data.get("identifier"), dict)
                        else str(data.get("identifier", "")),
                        "employment_type": str(data.get("employmentType", "")),
                    }
            except Exception:
                continue
        return None

    @staticmethod
    def _extract_avature_css(soup: BeautifulSoup) -> Dict[str, Any]:
        """Scrapes the generic 'Field: Value' structure used by most Avature portals."""
        data = {}

        # 1. Page Title (often the company name in Avature)
        page_title_tag = soup.find(class_="banner__text__title") or soup.find("h1")
        if page_title_tag:
            data["page_title"] = page_title_tag.get_text(strip=True)

        # 2. Field/Value pairs
        for field in soup.select(".article__content__view__field"):
            label = field.select_one(".article__content__view__field__label")
            value = field.select_one(".article__content__view__field__value")

            if label and value:
                raw_key = (
                    label.get_text(strip=True)
                    .lower()
                    .replace(":", "")
                    .replace(" ", "_")
                    .strip()
                )
                val_text = value.get_text(strip=True)
                data[raw_key] = val_text

                # Intelligent Redirection to core fields
                # If we find a field specifically called 'job_title', prioritize it over 'title'
                if raw_key in ["job_title", "title", "position"]:
                    data["title"] = val_text
                elif raw_key in [
                    "location",
                    "city",
                    "working_location",
                    "primary_location",
                ]:
                    data["location"] = val_text
                elif raw_key in ["ref_#", "reference", "job_id", "requisition_id"]:
                    data["job_id"] = val_text
                elif raw_key in ["date_published", "posted_date", "date_posted"]:
                    data["date_posted"] = val_text
                elif raw_key in ["working_time", "employment_type", "contract_type"]:
                    data["employment_type"] = val_text

            # 3. Description heuristic (large text blocks without labels)
            elif value and not label:
                text_content = value.get_text(strip=True)
                if len(text_content) > 200:
                    data["description"] = str(value)

        # Final check: if no explicit 'title' field found from content, use page_title
        if not data.get("title") and data.get("page_title"):
            data["title"] = data["page_title"]

        return data

    @staticmethod
    def _extract_meta_tags(soup: BeautifulSoup) -> Dict[str, Any]:
        """Fallback: Grabs OpenGraph metadata."""
        data = {}
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")

        if og_title:
            data["title"] = og_title["content"]
        if og_desc:
            data["description"] = og_desc["content"]

        return data

    @staticmethod
    def _parse_schema_location(loc_data: Any) -> Optional[str]:
        if not loc_data:
            return None
        if isinstance(loc_data, str):
            return loc_data

        address = loc_data.get("address", {})
        if isinstance(address, str):
            return address

        parts = [
            address.get("addressLocality"),
            address.get("addressRegion"),
            address.get("addressCountry"),
        ]
        return ", ".join([p for p in parts if p])

    @staticmethod
    def _to_job_entry(
        data: Dict[str, Any], url: str, base_company: str, strategy: str
    ) -> JobEntry:
        """Converts raw strategy data into a standardized JobEntry model with deduplication."""
        # Core standard fields
        title = data.get("title") or "Untitled Position"
        company = data.get("company") or base_company
        location = data.get("location") or "Remote / Not Specified"
        description = data.get("description")
        job_id = data.get("job_id")
        date_posted = data.get("date_posted")
        employment_type = data.get("employment_type")

        # Clean up metadata:
        # We remove keys that are already promoted to core fields (including common aliases)
        # to keep the JSON output clean and non-redundant.
        standard_aliases = [
            "title",
            "job_title",
            "position",
            "page_title",
            "location",
            "city",
            "working_location",
            "primary_location",
            "job_id",
            "ref_#",
            "reference",
            "requisition_id",
            "date_posted",
            "date_published",
            "posted_date",
            "employment_type",
            "working_time",
            "contract_type",
            "description",
            "company",
        ]
        metadata = {k: v for k, v in data.items() if k not in standard_aliases}
        metadata["parsing_strategy"] = strategy

        return JobEntry(
            title=title,
            company=company,
            location=location,
            description=description,
            application_url=url,
            job_id=job_id,
            date_posted=date_posted,
            employment_type=employment_type,
            metadata=metadata,
        )
