# Avature Adaptive Scraper Engine V2

A high-performance scraping infrastructure for extracting job inventory across the Avature ecosystem.

## Setup

```bash
uv sync
```

## Usage

Discover and scrape jobs from a list of Avature domains:

```bash
python main.py --input input/domains.txt --output output/jobs.jsonl
```

## Key Features

- **Sitemap Harvesting:** Bypasses UI limitations to get 100% of job listings.
- **Async HTTPX:** Scrapes hundreds of sites concurrently.
- **JSON-LD Parsing:** Uses structured data for high fidelity.
- **Pydantic Validation:** Ensures clean, database-ready output.
