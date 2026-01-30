# Take home assignment to scrape Avature

- took about 6 hours to do, with all sorts of ai assistance
- used tls_client to bypass waf
- used asyncio to speed up the process
- found 19333 jobs from 110 company domains (this low number is because some base domains in the provided list were not valid anymore)
- scraper has resumability support

This project aims to scrape job inventory from Avature portals using a combination of techniques to bypass WAFs and extract job data. I found several hurdles along the way, which i've documented below. I won't bother mentioning simple things like preferring web requests vs spinning up a full-blown web browser, etc. I'll instead mention the more complex hurdles that I overcame for Avature specifically.

I focused on ensuring I got around the WAFs in place, more than the data extraction process, as that can be improved more easily, once we have the HTML available to us. Given the 6-hour constraint, I prioritised Access & Coverage (solving the WAF) over granular parsing quality. The extraction logic is modular and ready for site-specific tuning

---

## Scraper

Avature is smart. They use aggressive WAFs (i think Akamai?), TLS fingerprinting, and strict HTTP/2 validation to deter bots. Here is the engineering implementation details in short:

### 1. Bypassing the "406 Not Acceptable" of Death

If you hit these sites with standard Python tools, you get a hard `406` error because the WAF checks your TLS Fingerprint. I swapped the transport layer for `tls_client` and strictly emulated the Firefox 117 cryptographic handshake (ciphers, extensions, curves). To the WAF, we are a legitimate browser as much as possible.

### 2. The HTTP/2 Protocol Violation

Even with the right fingerprint, we were initially blocked. It turns out that sending a `Connection: keep-alive` header over an HTTP/2 stream is technically illegal (per RFC 7540), but standard libraries do it anyway. The WAF was using this protocol violation to flag us. I made a custom header order that is strictly compliant, and this brought down the block rate.

### 3. The "Secret Handshake" (Session Caching)

Avature is stateful. You can't just hit an API endpoint directly; you need a specific session cookie (`ScustomPortal-ID`) that is only granted after a valid homepage visit. I implemented a Domain-Scoped Session Cache that performs this expensive "Cookie Handshake" once per domain, caches this _blessed_ session, and reuses it for thousands of subsequent API calls. This means that the script starts slow, but gets faster and faster as it caches more sessions.

### 4. The "Polymorphic" Extractor

Some Avature sites are modern (React/JSON), while others are... vintage (Server-side HTML). The scraper uses a waterfall strategy:

1. **Tier 1:** Checks for JSON-LD (Structured Data).
2. **Tier 2:** Attempts to inject into the Internal JSON API (`/SearchJobsData`) using the cached session.
3. **Tier 3:** Falls back to a Heuristic DOM Parser that aggregates fragmented HTML descriptions (handling quirks like the Consumer Direct Care site).

This is the bit that has the most room for improvement.

## Domain Discovery

The project brief asked to expand coverage, so I didn't use just the existing URLs. I implemented a discovery module that queries Certificate Transparency Logs (`crt.sh`) for wildcard certificates (`%.avature.net`). This allowed us to uncover internal and unlisted career portals that weren't in the public seed list, but this required cleaning as some of the domains were not valid anymore or were not career portals.

## Trade-offs

WAFs are probabilistic beasts. Even with a perfect TLS handshake, sometimes Akamai just decides it doesn't like your face (or in this case, your IP). I deliberately chose Architecture over Infrastructure. I didn't hook this up to a massive rotating residential proxy network because, well, I don't have a corporate credit card for this assignment. That means if you hammer a domain too hard, you might still catch a temporary timeout. The retry timeouts are large enough that the script will eventually get the data, but it might take a while.

To avoid this, I made the Resume System. If the script hits a brick wall, it gracefully saves its state and exits. You just grab a coffee, hit run again, and it picks up exactly where it left off. It’s not a crash; it’s a tactical pause.

## How to Run

This project uses `uv` for fast dependency management and execution.

1. **Install dependencies:**

   ```bash
   uv sync
   ```

2. **Discover Portals:** (Clean seed list & find new ones via CT logs)

   ```bash
   uv run main.py discover
   ```

3. **Harvest URLs:** (Find individual job links from discovered portals)

   ```bash
   uv run main.py harvest
   ```

4. **Scrape Jobs:** (Extract details to `output/v2_jobs.jsonl`)
   ```bash
   uv run main.py scrape --concurrency 20
   ```

---

_PSA: I really enjoyed working on this project, job or not! Thanks for the challenge Hamed!_ 🚀
