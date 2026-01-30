import asyncio
import logging
from pathlib import Path
from typing import List

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
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger("avature")
console = Console()


async def process_domain(domain: str, client: AsyncClient, discovery: DiscoveryEngine):
    logger.info(f"[bold blue]Processing domain:[/bold blue] {domain}")

    # Discovery phase
    job_urls = await discovery.find_job_urls_from_sitemap(domain)
    if not job_urls:
        logger.warning(
            f"No sitemap jobs found for {domain}. Falling back to API discovery would go here."
        )
        return []

    logger.info(f"Found {len(job_urls)} jobs for {domain}")

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
        ) as progress:
            task = progress.add_task(
                "[cyan]Scraping Avature Ecosystem...", total=len(domains)
            )

            for domain in domains:
                # We could use asyncio.gather for even more speed, but let's keep it readable
                domain_jobs = await process_domain(domain, client, discovery)
                all_jobs.extend(domain_jobs)
                progress.advance(task)

        # Save results
        output_path = Path(output_file)
        with open(output_path, "w") as f:
            for job in all_jobs:
                f.write(job.model_dump_json() + "\n")

        console.print(
            f"\n[bold green]Success![/bold green] Extracted {len(all_jobs)} jobs to {output_file}"
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
@click.option("--concurrency", default=20, help="Parallel validation concurrency.")
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
        ct_domains = asyncio.run(discovery.discover_from_ct_logs())
        all_potential_domains.update(ct_domains)
        logger.info(
            f"Total potential domains after CT discovery: {len(all_potential_domains)}"
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
@click.option("--output", default="output/v2_jobs.jsonl", help="Output JSONL file.")
def scrape(input, output):
    """Scrape jobs from discovered portals."""
    if not Path(input).exists():
        console.print(
            f"[red]Error:[/red] Input file {input} not found. Run 'discover' first."
        )
        return

    with open(input, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    asyncio.run(run_scraper(domains, output))


if __name__ == "__main__":
    cli()
