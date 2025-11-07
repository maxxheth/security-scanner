import sys
import requests
from bs4 import BeautifulSoup
import os
import re
from urllib.parse import urlparse, parse_qs, urljoin
import time
import argparse
import yaml
import json
from scrapy.spiders import Spider
from scrapy.crawler import CrawlerProcess
import nmap

class WordPressSpider(Spider):
    name = 'wordpress_spider'
    
    def __init__(self, start_url, max_pages=10, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc]
        self.max_pages = int(max_pages)
        self.page_count = 0
        self.plugins = set()
        self.themes = set()
    
    def parse(self, response):
        if self.page_count >= self.max_pages:
            return
        self.page_count += 1
        
        # Extract plugins and themes from current page
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['link', 'script'], href=True):
            href = tag['href']
            slug, version = extract_slug_version(href, 'plugins')
            if slug:
                self.plugins.add((slug, version))
            slug, version = extract_slug_version(href, 'themes')
            if slug:
                self.themes.add((slug, version))
        
        # Follow links to other pages
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('/'):
                href = urljoin(response.url, href)
            if urlparse(href).netloc == self.allowed_domains[0]:
                yield response.follow(href, self.parse)
    
    def closed(self, reason):
        # Save results to file when spider closes
        import json
        results = {
            'plugins': dict(self.plugins),
            'themes': dict(self.themes)
        }
        with open('/tmp/scrapy_results.json', 'w') as f:
            json.dump(results, f)

def extract_slug_version(href, content_type):
    """
    Extract plugin/theme slug and version from href.
    href like: /wp-content/plugins/akismet/akismet.php?ver=1.2.3
    """
    if content_type not in href:
        return None, None
    # Find the slug
    match = re.search(rf'/wp-content/{content_type}/([^/]+)/', href)
    if not match:
        return None, None
    slug = match.group(1)
    # Extract version from query
    parsed = urlparse(href)
    query = parse_qs(parsed.query)
    version = query.get('ver', [None])[0]
    return slug, version

def initial_scan(url, crawl=False, max_pages=10):
    plugins = {}
    themes = {}
    
    if crawl:
        # Use Scrapy to crawl multiple pages
        process = CrawlerProcess({
            'USER_AGENT': 'wordpress-scanner (+http://www.yourdomain.com)',
            'ROBOTSTXT_OBEY': True,
            'LOG_LEVEL': 'ERROR',  # Reduce log noise
        })
        
        # Pass parameters to spider class
        process.crawl(WordPressSpider, start_url=url, max_pages=max_pages)
        process.start()
        
        # Read results from file
        try:
            with open('/tmp/scrapy_results.json', 'r') as f:
                results = json.load(f)
            plugins = results.get('plugins', {})
            themes = results.get('themes', {})
        except:
            plugins, themes = {}, {}
            print("Crawling completed, but no results found. Falling back to homepage scan.")
            # Fallback to homepage
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                for tag in soup.find_all(['link', 'script'], href=True):
                    href = tag['href']
                    slug, version = extract_slug_version(href, 'plugins')
                    if slug:
                        plugins[slug] = version
                    slug, version = extract_slug_version(href, 'themes')
                    if slug:
                        themes[slug] = version
            except requests.RequestException as e:
                print(f"Error fetching {url}: {e}")
    else:
        # Simple scan of homepage
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return {}, {}

        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['link', 'script'], href=True):
            href = tag['href']
            slug, version = extract_slug_version(href, 'plugins')
            if slug:
                plugins[slug] = version
            slug, version = extract_slug_version(href, 'themes')
            if slug:
                themes[slug] = version

    return plugins, themes

def user_enumeration(url):
    try:
        response = requests.get(f"{url.rstrip('/')}/wp-json/wp/v2/users", timeout=10)
        response.raise_for_status()
        users = response.json()
    except requests.RequestException as e:
        print(f"Error enumerating users: {e}")
        return []

    user_info = []
    for user in users:
        user_info.append({
            'id': user.get('id'),
            'username': user.get('name'),
            'roles': user.get('roles', [])
        })
    return user_info

def check_vulnerabilities(items, api_key, item_type):
    if not api_key:
        print(f"No API key provided, skipping {item_type} vulnerability checks.")
        return []
    print(f"Checking {len(items)} {item_type} for vulnerabilities...")
    vulnerable = []
    headers = {'Authorization': f'Token token={api_key}'}
    for slug, version in items.items():
        try:
            response = requests.get(f'https://wpscan.com/api/v3/{item_type}/{slug}', headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    for vuln in vulns:
                        affected_versions = vuln.get('affected_in', [])
                        if not version or any(version in aff or aff in version for aff in affected_versions):
                            vulnerable.append({
                                'slug': slug,
                                'version': version,
                                'vulnerability': vuln
                            })
                            break  # report if any vuln matches
            else:
                if response.status_code != 404:
                    print(f"Failed to check {item_type} {slug}: HTTP {response.status_code} - {response.text[:100]}")
            time.sleep(1)  # Rate limit delay
        except requests.RequestException as e:
            print(f"Error checking {item_type} {slug}: {e}")
    return vulnerable

def port_scan(target, ports):
    try:
        nm = nmap.PortScanner()
        port_str = ','.join(map(str, ports))
        nm.scan(target, port_str)
        results = {}
        for host in nm.all_hosts():
            results[host] = {}
            for proto in nm[host].all_protocols():
                results[host][proto] = {}
                lport = nm[host][proto].keys()
                for port in lport:
                    results[host][proto][port] = nm[host][proto][port]
        return results
    except Exception as e:
        print(f"Port scan error: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description='WordPress Security Scanner')
    parser.add_argument('--url', help='Target WordPress URL')
    parser.add_argument('--config', help='YAML config file')
    parser.add_argument('--api-key', help='WPScan API key')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling for more pages')
    parser.add_argument('--max-pages', type=int, default=10, help='Max pages to crawl')
    parser.add_argument('--port-scan', action='store_true', help='Enable port scanning')
    parser.add_argument('--ports', nargs='+', type=int, default=[80, 443, 3306, 22], help='Ports to scan')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')

    args = parser.parse_args()

    # Load config if provided
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)

    # Override with CLI args
    url = args.url or config.get('url')
    api_key = args.api_key or config.get('wpscan_api_key') or os.getenv('WPSCAN_API_KEY')
    crawl = args.crawl or config.get('scan_options', {}).get('crawl', False)
    max_pages = args.max_pages or config.get('scan_options', {}).get('max_pages', 10)
    port_scan_enabled = args.port_scan or config.get('scan_options', {}).get('port_scan', False)
    ports = args.ports or config.get('scan_options', {}).get('ports', [80, 443, 3306, 22])
    output_file = args.output or config.get('output', {}).get('file')
    output_format = args.format or config.get('output', {}).get('format', 'text')

    if not url:
        print("URL is required. Use --url or config file.")
        sys.exit(1)

    print(f"Scanning {url}...")

    plugins, themes = initial_scan(url, crawl, max_pages)
    print(f"Found {len(plugins)} plugins: {list(plugins.keys())}")
    print(f"Found {len(themes)} themes: {list(themes.keys())}")

    users = user_enumeration(url)
    print(f"Enumerated {len(users)} users")

    plugin_vulns = check_vulnerabilities(plugins, api_key, 'plugins')
    theme_vulns = check_vulnerabilities(themes, api_key, 'themes')

    port_results = {}
    if port_scan_enabled:
        target = urlparse(url).netloc
        port_results = port_scan(target, ports)
        print(f"Port scan results: {port_results}")

    # Prepare report
    report = {
        'url': url,
        'plugins': plugins,
        'themes': themes,
        'users': users,
        'vulnerable_plugins': plugin_vulns,
        'vulnerable_themes': theme_vulns,
        'port_scan': port_results
    }

    if output_format == 'json':
        output = json.dumps(report, indent=2)
    else:
        output = f"""
=== REPORT ===

Users:
{chr(10).join(f"  ID: {user['id']}, Username: {user['username']}, Roles: {user['roles']}" for user in users)}

Vulnerable Plugins:
{chr(10).join(f"  {vuln['slug']} (v{vuln['version']}): {vuln['vulnerability']['title']}" for vuln in plugin_vulns)}

Vulnerable Themes:
{chr(10).join(f"  {vuln['slug']} (v{vuln['version']}): {vuln['vulnerability']['title']}" for vuln in theme_vulns)}

Port Scan Results:
{port_results}
"""

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        print(f"Report saved to {output_file}")
    else:
        print(output)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()