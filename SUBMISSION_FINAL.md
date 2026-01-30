# Technical Submission: Avature Adaptive Scraper Engine (V2)

**Candidate:** [Your Name]  
**Approach:** Distributed Async Engine with Sitemap Harvesting  
**Execution Time:** ~6 hours (V2 Refactor)

---

## 🚀 Executive Summary

This project implements a high-performance, asynchronous scraping engine designed for industrial-scale job extraction from the Avature ecosystem.

**Key Technical Achievements:**

- **Zero-Config Discovery:** Developed a `SitemapExplorer` that bypasses search page limitations by harvesting XML sitemaps via `robots.txt` discovery.
- **Async Efficiency:** Built on `httpx` and `asyncio`, the engine handles concurrent processing of hundreds of domains with minimal memory footprint.
- **Structured Data Priority:** Implements a parsing pipeline that prioritizes **JSON-LD (Schema.org)** metadata over fragile HTML selectors, ensuring high data fidelity even when site layouts change.
- **Robust Modeling:** Utilizes **Pydantic** for runtime data validation and schema enforcement.

---

## 🛠 Architecture & Engineering Logic

### 1. The "Sitemap-First" Discovery Strategy

The primary challenge with Avature (and most ATS platforms) is that the "Search" UI often caps results at 500–1,000 jobs. To achieve **100% inventory coverage**, I implemented a sitemap harvesting strategy:

1.  **Robots.txt Analysis:** Fetch `/robots.txt` for every discovered domain.
2.  **Sitemap Traversal:** Identify `sitemap_index.xml` and traverse sub-sitemaps specifically tagged for jobs.
3.  **Direct URL Extraction:** Extract permanent `/JobDetail/` URLs directly from XML, bypassing the need for slow, page-by-page DOM interaction.

### 2. High-Performance Async Client

Unlike standard procedural scrapers, this engine uses a custom `AsyncClient` wrapper around `httpx`:

- **Connection Pooling:** Maintains persistent TCP connections to reduce handshake overhead.
- **Adaptive Throttling:** Built-in limits on concurrent connections to avoid triggering anti-bot protection while maintaining speed.
- **Error Resilience:** Systematic handling of SSL/TLS edge cases common in enterprise portals.

### 3. The Parsing Pipeline (Polyglot Parser)

Website parsing is traditionally the most fragile part of a scraper. V2 solves this by using a prioritized pipeline:

- **Tier 1 (JSON-LD):** The engine first looks for `<script type="application/ld+json">`. This provides clean, structured data intended for Google Jobs.
- **Tier 2 (Fallback Heuristics):** If structured data is missing, the engine falls back to a CSS-independent text extraction layer.

---

## 📊 Comparison with Standard Approaches

| Feature           | Standard "Script" Scrapers       | **Avature Engine V2 (This Solution)**    |
| :---------------- | :------------------------------- | :--------------------------------------- |
| **Concurrency**   | Threads/Processes (Heavy)        | **Async Events (Ultra-Lightweight)**     |
| **Dataset Depth** | UI Page Limits (Partial)         | **Sitemap Harvesting (Total Inventory)** |
| **Reliability**   | CSS Selectors (High Maintenance) | **JSON-LD / Schema (Self-Healing)**      |
| **UX**            | Console Logs                     | **Interactive Rich CLI**                 |

---

## 📁 Project Structure

```text
.
├── main.py              # CLI Entry point (click & rich)
├── input/               # Seed domains list (e.g., domains.txt)
├── output/              # Final JSONL datasets
├── scraper/             # The Core Package
│   ├── client.py        # Async HTTP engine
│   ├── discovery.py     # Sitemap & robots logic
│   ├── parsing.py       # JSON-LD & DOM extraction
│   └── models.py        # Pydantic data schemas
└── requirements.txt     # Modern dependency tree
```

---

## ⚡ Instructions to Run

1. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Engine:**

   ```bash
   python main.py --input input/domains.txt --output output/jobs.jsonl
   ```

3. **Check the Output:**
   The output is a flat JSONL file where each line is a validated `JobEntry` object, ready for database ingestion.
