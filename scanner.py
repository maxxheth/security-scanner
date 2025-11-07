import sys
import requests
from bs4 import BeautifulSoup
import os
import re
from urllib.parse import urlparse, parse_qs
import time

def extract_slug_version(href, content_type):
    """
    Extract plugin/theme slug and version from href.
    href like: /wp-content/plugins/akismet/akismet.php?ver=4.2.2
    or /wp-content/themes/twentytwenty/style.css?ver=1.0
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

def initial_scan(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return [], []

    soup = BeautifulSoup(response.text, 'html.parser')
    plugins = {}
    themes = {}

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

def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <wordpress_url>")
        sys.exit(1)

    url = sys.argv[1]
    api_key = os.getenv('WPSCAN_API_KEY')

    print(f"Scanning {url}...")

    plugins, themes = initial_scan(url)
    print(f"Found {len(plugins)} plugins: {list(plugins.keys())}")
    print(f"Found {len(themes)} themes: {list(themes.keys())}")

    users = user_enumeration(url)
    print(f"Enumerated {len(users)} users")

    plugin_vulns = check_vulnerabilities(plugins, api_key, 'plugins')
    theme_vulns = check_vulnerabilities(themes, api_key, 'themes')

    # Report
    print("\n=== REPORT ===")
    print("\nUsers:")
    for user in users:
        print(f"  ID: {user['id']}, Username: {user['username']}, Roles: {user['roles']}")

    print("\nVulnerable Plugins:")
    for vuln in plugin_vulns:
        print(f"  {vuln['slug']} (v{vuln['version']}): {vuln['vulnerability']['title']}")

    print("\nVulnerable Themes:")
    for vuln in theme_vulns:
        print(f"  {vuln['slug']} (v{vuln['version']}): {vuln['vulnerability']['title']}")

if __name__ == '__main__':
    main()