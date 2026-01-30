# Avature Adaptive Scraper Engine V2

A high-performance scraping infrastructure for extracting job inventory across the Avature ecosystem. Engineered for speed, discovery, and reliability.

## 🚀 Quick Start

1. **Setup:**

   ```bash
   uv sync
   ```

2. **Discover:** (Analyze raw URLs and find new portals via CT logs)

   ```bash
   uv run main.py discover
   ```

3. **Scrape:** (Harvest jobs from validated portals)
   ```bash
   uv run main.py scrape
   ```

## 🛠 Features

- **Automated Discovery:** Queries Certificate Transparency logs to find hundreds of active Avature portals beyond the starter pack.
- **Validation Engine:** Automatically filters out sandboxes, internal portals, and "noindex" sites using signature verification.
- **Sitemap Harvesting:** Bypasses search UI limitations to capture 100% of job inventory via XML sitemaps.
- **Async Speed:** Built with `httpx` and `asyncio` for high-concurrency processing with minimal memory footprint.
- **Structured Extraction:** Prioritizes **JSON-LD (Schema.org)** data for perfect fidelity, falling back to heuristic parsing only when necessary.
- **Fingerprint Bypass:** Uses `curl_cffi` for browser impersonation to bypass bot detection on sensitive endpoints.

## 📁 Project Structure

- `main.py`: Command-line interface.
- `scraper/portal_discovery.py`: logic for finding and validating portals.
- `scraper/discovery.py`: logic for traversing sitemaps and finding job links.
- `scraper/parsing.py`: logic for extracting data from job pages.
- `pyproject.toml`: Modern dependency management.
