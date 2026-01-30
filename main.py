import asyncio
import logging
from pathlib import Path
from typing import List
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.logging import RichHandler

from scraper.client import AsyncClient
from scraper.discovery import DiscoveryEngine
from scraper.parsing import JobParser

# Set up beautiful logging
console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger("avature")


async def process_domain(domain: str, client: AsyncClient, discovery: DiscoveryEngine):
    # Discovery phase
    job_urls = await discovery.find_job_urls_from_sitemap(domain)
    if not job_urls:
        return []

    jobs = []
    # Scraping phase
    for url in list(job_urls)[:100]:  # Limit for POC
        resp = await client.get(url)
        if resp:
            job = JobParser.extract_from_html(
                resp.text, url, domain.split(".")[0].title()
            )
            if job:
                jobs.append(job)

    return jobs


async def run_scraper(domains: List[str], output_file: str):
    client = AsyncClient(max_connections=50)
    discovery = DiscoveryEngine(client)
    all_jobs = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Scraping Jobs...", total=len(domains))

            for domain in domains:
                progress.update(
                    task,
                    description=f"[cyan]Scraping:[/cyan] [bold]{urlparse(domain).netloc}[/bold]",
                )
                domain_jobs = await process_domain(domain, client, discovery)
                all_jobs.extend(domain_jobs)
                progress.advance(task)

        # Save results
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for job in all_jobs:
                f.write(job.model_dump_json() + "\n")

        console.print(
            f"\n[bold green]Success![/bold green] Extracted {len(all_jobs)} jobs to {output_file}"
        )

    finally:
        await client.close()


async def run_harvest(domains: List[str], output_file: str, concurrency: int = 20):
    client = AsyncClient(max_connections=concurrency + 10)
    discovery = DiscoveryEngine(client)
    all_job_urls = set()
    semaphore = asyncio.Semaphore(concurrency)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Harvesting Job URLs...", total=len(domains))

            async def harvest_one(domain, index):
                async with semaphore:
                    # Staggered start
                    await asyncio.sleep(index * 0.2 % 3)

                    progress.update(
                        task,
                        description=f"[cyan]Harvesting:[/cyan] [bold]{urlparse(domain).netloc}[/bold]",
                    )
                    try:
                        job_urls = await discovery.find_job_urls_from_sitemap(domain)
                        if job_urls:
                            all_job_urls.update(job_urls)
                    except Exception as e:
                        logger.error(f"Error harvesting {domain}: {e}")
                    finally:
                        progress.advance(task)

            await asyncio.gather(
                *(harvest_one(domain, i) for i, domain in enumerate(domains))
            )

        # Save results
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for url in sorted(list(all_job_urls)):
                f.write(url + "\n")

        console.print(
            f"\n[bold green]Success![/bold green] Harvested {len(all_job_urls)} unique job URLs to {output_file}"
        )

    finally:
        await client.close()


@click.group()
def cli():
    """Avature Adaptive Scraper Engine V2"""
    pass


@cli.command()
@click.option(
    "--input-file", default="input/urls.txt", help="Raw list of URLs to clean."
)
@click.option(
    "--output-file", default="input/domains.txt", help="File to save cleaned domains."
)
@click.option(
    "--use-ct",
    is_flag=True,
    default=True,
    help="Use Certificate Transparency logs for discovery.",
)
@click.option(
    "--validate",
    is_flag=True,
    default=True,
    help="Validate discovered portals before saving.",
)
@click.option("--concurrency", default=10, help="Parallel validation concurrency.")
def discover(input_file, output_file, use_ct, validate, concurrency):
    """Discover and normalize Avature portals."""
    from scraper.portal_discovery import PortalDiscovery

    console.print("[bold cyan]Starting Portal Discovery...[/bold cyan]")
    discovery = PortalDiscovery()
    all_potential_domains = set()

    # 1. Process local urls.txt if it exists
    path = Path(input_file)
    if path.exists():
        with open(path, "r") as f:
            for line in f:
                normalized = discovery.normalize_to_base(line)
                if normalized:
                    all_potential_domains.add(normalized)
        logger.info(
            f"Loaded {len(all_potential_domains)} potential base domains from {input_file}"
        )
    else:
        logger.warning(f"Seed file {input_file} not found. Starting with empty list.")

    # 2. Advanced discovery via CT Logs
    if use_ct:
        initial_count = len(all_potential_domains)
        ct_domains = asyncio.run(discovery.discover_from_ct_logs())
        all_potential_domains.update(ct_domains)
        added_count = len(all_potential_domains) - initial_count

        logger.info(
            f"CT Discovery complete: added {added_count} new potential domains."
        )
        logger.info(
            f"Total potential domains to validate: {len(all_potential_domains)}"
        )

    # 3. Validation phase
    if validate and all_potential_domains:
        console.print(
            f"[bold yellow]Validating {len(all_potential_domains)} portals...[/bold yellow]"
        )
        final_domains = asyncio.run(
            discovery.validate_portals(
                list(all_potential_domains), concurrency=concurrency
            )
        )
    else:
        final_domains = sorted(list(all_potential_domains))

    # 4. Save unique cleaned domains
    with open(output_file, "w") as f:
        for d in final_domains:
            f.write(d + "\n")

    console.print(
        f"[bold green]Success![/bold green] Saved {len(final_domains)} validated portals to {output_file}"
    )


@cli.command()
@click.option("--input", default="input/domains.txt", help="File with Avature domains.")
@click.option(
    "--output", default="input/job_urls.txt", help="Output file for job URLs."
)
@click.option("--limit", type=int, help="Restrict to N random companies for testing.")
@click.option("--concurrency", default=10, help="Number of concurrent discovery tasks.")
def harvest(input, output, limit, concurrency):
    """Harvest all job URLs from discovered portals."""
    if not Path(input).exists():
        console.print(
            f"[red]Error:[/red] Input file {input} not found. Run 'discover' first."
        )
        return

    with open(input, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    if limit and limit > 0:
        import random

        selected_domains = random.sample(domains, min(limit, len(domains)))
        console.print(
            f"[bold yellow]Testing Mode:[/bold yellow] Restricted to {len(selected_domains)} random companies."
        )
        domains = selected_domains

    asyncio.run(run_harvest(domains, output, concurrency=concurrency))


@cli.command()
@click.option("--input", default="input/job_urls.txt", help="File with Job URLs.")
@click.option("--output", default="output/v2_jobs.jsonl", help="Output JSONL file.")
@click.option("--limit", type=int, help="Limit number of jobs to scrape.")
@click.option("--concurrency", default=5, help="Number of concurrent scraper tasks.")
def scrape(input, output, limit, concurrency):
    """Scrape details from harvested job URLs."""
    if not Path(input).exists():
        console.print(
            f"[red]Error:[/red] Input file {input} not found. Run 'harvest' first."
        )
        return

    with open(input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    # --- Domain Interleaving Logic ---
    # To avoid rate-limiting, we group by domain and interleave the URLs
    from collections import defaultdict

    domain_map = defaultdict(list)
    for url in urls:
        domain = urlparse(url).netloc
        domain_map[domain].append(url)

    # Shuffle URLs within each domain
    import random

    for domain in domain_map:
        random.shuffle(domain_map[domain])

    # Interleave (Round-Robin)
    interleaved_urls = []
    max_len = max(len(v) for v in domain_map.values()) if domain_map else 0
    domains_list = list(domain_map.keys())
    # We shuffle domain order too for extra randomness
    random.shuffle(domains_list)

    for i in range(max_len):
        for domain in domains_list:
            if i < len(domain_map[domain]):
                interleaved_urls.append(domain_map[domain][i])

    urls = interleaved_urls

    if limit and limit > 0:
        urls = urls[:limit]
        console.print(
            f"[bold yellow]Testing Mode:[/bold yellow] Using {len(urls)} interleaved jobs from {len(domain_map)} domains."
        )

    async def scrape_jobs():
        client = AsyncClient(max_connections=concurrency + 10)
        all_jobs = []
        semaphore = asyncio.Semaphore(concurrency)

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Scraping Jobs...", total=len(urls))

                async def scrape_one(url, index):
                    async with semaphore:
                        # Staggered start to avoid concurrent bursts
                        await asyncio.sleep(index * 0.1 % 2)

                        progress.update(
                            task,
                            description=f"[cyan]Scraping:[/cyan] {urlparse(url).netloc}...",
                        )
                        try:
                            resp = await client.get(url)
                            if resp:
                                domain = urlparse(url).netloc
                                job = JobParser.extract_from_html(
                                    resp.text, url, domain.split(".")[0].title()
                                )
                                if job:
                                    all_jobs.append(job)
                        except Exception as e:
                            logger.error(f"Error scraping {url}: {e}")
                        finally:
                            progress.advance(task)

                await asyncio.gather(
                    *(scrape_one(url, i) for i, url in enumerate(urls))
                )

            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                for job in all_jobs:
                    f.write(job.model_dump_json() + "\n")
            console.print(
                f"\n[bold green]Success![/bold green] Extracted {len(all_jobs)} jobs to {output}"
            )
        finally:
            await client.close()

    asyncio.run(scrape_jobs())


if __name__ == "__main__":
    cli()
