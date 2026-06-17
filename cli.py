import argparse
import os
import sqlite3
import json
import csv
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

load_dotenv()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
DB_PATH = "threat_intel.db"
console = Console()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS enrichments (
        ioc_value TEXT PRIMARY KEY,
        ioc_type TEXT DEFAULT 'ip',
        source TEXT,
        abuse_confidence INTEGER,
        country TEXT,
        usage_type TEXT,
        isp TEXT,
        details TEXT,
        tags TEXT,
        last_queried TEXT
    )''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def enrich_with_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None, "No AbuseIPDB API key found in .env"
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "details": json.dumps(data)
        }, None
    except Exception as e:
        return None, str(e)

def enrich_with_ipapi(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org,as"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }
    except:
        return None

def save_or_update_enrichment(ioc_value, enrichment_data, tags=None):
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    existing = c.execute("SELECT tags FROM enrichments WHERE ioc_value = ?", (ioc_value,)).fetchone()
    current_tags = json.loads(existing["tags"]) if existing and existing["tags"] else []

    if tags:
        for t in tags:
            if t not in current_tags:
                current_tags.append(t)

    c.execute('''INSERT OR REPLACE INTO enrichments 
        (ioc_value, ioc_type, source, abuse_confidence, country, usage_type, isp, details, tags, last_queried)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (ioc_value, "ip", "abuseipdb+ipapi",
         enrichment_data.get("abuse_confidence"),
         enrichment_data.get("country"),
         enrichment_data.get("usage_type"),
         enrichment_data.get("isp"),
         enrichment_data.get("details"),
         json.dumps(current_tags),
         now))
    conn.commit()
    conn.close()

def print_enrichment(row):
    if not row:
        return

    table = Table(title=f"[bold]{row['ioc_value']}[/bold] ({row['ioc_type']})", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Source", row['source'])
    table.add_row("Abuse Confidence", str(row['abuse_confidence']))
    table.add_row("Country", row['country'] or "N/A")
    table.add_row("Usage Type", row['usage_type'] or "N/A")
    table.add_row("ISP", row['isp'] or "N/A")

    tags = json.loads(row['tags']) if row['tags'] else []
    table.add_row("Tags", ", ".join(tags) if tags else "None")
    table.add_row("Last Queried", row['last_queried'])

    console.print(Panel(table, border_style="blue"))

def check_ip(ip, tags=None, force=False):
    init_db()
    conn = get_db_connection()
    existing = conn.execute("SELECT * FROM enrichments WHERE ioc_value = ?", (ip,)).fetchone()
    conn.close()

    if existing and not force:
        console.print(f"[yellow][CACHE][/yellow] Found existing record for {ip}")
        print_enrichment(existing)
        return

    console.print(f"[cyan][ENRICH][/cyan] Querying APIs for {ip}...")
    abuse_data, err = enrich_with_abuseipdb(ip)
    if err:
        console.print(f"[red]AbuseIPDB error:[/red] {err}")
        abuse_data = {}

    geo_data = enrich_with_ipapi(ip) or {}
    combined = {**abuse_data, **geo_data}

    if not combined:
        console.print("[red]No enrichment data retrieved.[/red]")
        return

    save_or_update_enrichment(ip, combined, tags)
    console.print(f"[green][SUCCESS][/green] Enriched and stored {ip}")

    conn = get_db_connection()
    row = conn.execute("SELECT * FROM enrichments WHERE ioc_value = ?", (ip,)).fetchone()
    conn.close()
    print_enrichment(row)

def query_ioc(value=None, tag=None):
    init_db()
    conn = get_db_connection()
    if value:
        row = conn.execute("SELECT * FROM enrichments WHERE ioc_value = ?", (value,)).fetchone()
        print_enrichment(row)
    elif tag:
        rows = conn.execute("SELECT * FROM enrichments WHERE tags LIKE ?", (f'%"{tag}"%',)).fetchall()
        for row in rows:
            print_enrichment(row)
    else:
        rows = conn.execute("SELECT * FROM enrichments ORDER BY last_queried DESC LIMIT 20").fetchall()
        for row in rows:
            print_enrichment(row)
    conn.close()

def add_tag(ioc_value, new_tag):
    init_db()
    conn = get_db_connection()
    row = conn.execute("SELECT tags FROM enrichments WHERE ioc_value = ?", (ioc_value,)).fetchone()
    if not row:
        console.print(f"[red]No record for {ioc_value}. Run 'check' first.[/red]")
        conn.close()
        return
    current = json.loads(row["tags"]) if row["tags"] else []
    if new_tag not in current:
        current.append(new_tag)
        conn.execute("UPDATE enrichments SET tags = ? WHERE ioc_value = ?", (json.dumps(current), ioc_value))
        conn.commit()
        console.print(f"[green]Added tag '{new_tag}' to {ioc_value}[/green]")
    else:
        console.print("Tag already exists.")
    conn.close()

def export_data(format_type="json", output_file=None, tag=None):
    init_db()
    conn = get_db_connection()

    if tag:
        rows = conn.execute("SELECT * FROM enrichments WHERE tags LIKE ?", (f'%"{tag}"%',)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM enrichments").fetchall()

    conn.close()

    if not rows:
        console.print("[yellow]No records found to export.[/yellow]")
        return

    data = [dict(row) for row in rows]

    if format_type == "json":
        if not output_file:
            output_file = "enrichments_export.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Exported {len(data)} records to {output_file}[/green]")

    elif format_type == "csv":
        if not output_file:
            output_file = "enrichments_export.csv"
        if data:
            keys = data[0].keys()
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)
            console.print(f"[green]Exported {len(data)} records to {output_file}[/green]")

def batch_process(file_path, tags=None, force=False):
    if not os.path.exists(file_path):
        console.print(f"[red]File not found: {file_path}[/red]")
        return

    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:   # utf-8-sig handles BOM
            ips = [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        console.print("[red]Encoding error reading the file. Try saving ips.txt as UTF-8 in VS Code.[/red]")
        return

    if not ips:
        console.print("[yellow]No valid IPs found in the file.[/yellow]")
        return

    console.print(f"[cyan]Processing {len(ips)} IPs from {file_path}...[/cyan]")

    for ip in track(ips, description="Enriching IPs..."):
        check_ip(ip, tags=tags, force=force)

def main():
    parser = argparse.ArgumentParser(description="Threat Intel Enricher CLI")
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Enrich and store an IP")
    check_parser.add_argument("ip", help="IP address to check")
    check_parser.add_argument("--tag", action="append", help="Add tag(s)")
    check_parser.add_argument("--force", action="store_true", help="Force fresh API query")

    query_parser = subparsers.add_parser("query", help="Query stored enrichments")
    query_parser.add_argument("--ip", help="Specific IP")
    query_parser.add_argument("--tag", help="Filter by tag")

    tag_parser = subparsers.add_parser("tag", help="Add tag to existing IOC")
    tag_parser.add_argument("ip", help="IP address")
    tag_parser.add_argument("tag", help="Tag to add")

    export_parser = subparsers.add_parser("export", help="Export data to JSON or CSV")
    export_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Export format")
    export_parser.add_argument("--output", help="Output filename")
    export_parser.add_argument("--tag", help="Only export records with this tag")

    batch_parser = subparsers.add_parser("batch", help="Process multiple IPs from a text file")
    batch_parser.add_argument("--file", required=True, help="Path to text file with one IP per line")
    batch_parser.add_argument("--tag", action="append", help="Add tag(s) to all IPs")
    batch_parser.add_argument("--force", action="store_true", help="Force fresh API queries")

    list_parser = subparsers.add_parser("list", help="List recent enrichments")

    args = parser.parse_args()

    if args.command == "check":
        check_ip(args.ip, args.tag, args.force)
    elif args.command == "query":
        query_ioc(args.ip, args.tag)
    elif args.command == "tag":
        add_tag(args.ip, args.tag)
    elif args.command == "export":
        export_data(args.format, args.output, args.tag)
    elif args.command == "batch":
        batch_process(args.file, args.tag, args.force)
    elif args.command == "list":
        query_ioc()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()