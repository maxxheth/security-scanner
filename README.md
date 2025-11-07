# WordPress Security Scanner

A comprehensive Dockerized Python script to audit WordPress sites for vulnerabilities, enumerate users, scan ports, and crawl multiple pages.

## Features

- **Multi-page Crawling**: Uses Scrapy to crawl and scan multiple pages for plugins/themes
- **User Enumeration**: Fetches users via WordPress REST API
- **Vulnerability Checks**: Queries WPScan API for known vulnerabilities
- **Port Scanning**: Uses nmap to scan server ports
- **Configurable**: YAML config files and CLI flags
- **Multiple Output Formats**: JSON and text reports

## Prerequisites

- Docker
- WPScan API Key (optional, for vulnerability checks). Sign up at https://wpscan.com/api/

## Usage

### Using Docker Compose (Recommended)

1. Set your WPScan API key in an environment variable or config:
   ```bash
   export WPSCAN_API_KEY=your_api_key_here
   ```

2. Run the scanner:
   ```bash
   docker compose run --rm scanner --url https://example.com --crawl --port-scan
   ```

### Using Docker Directly

```bash
docker run --rm -e WPSCAN_API_KEY=your_api_key_here wp-scanner --url https://example.com --crawl --max-pages 20
```

### Using Config File

Create a `config.yaml` file (see `config.yaml` for example), then:

```bash
docker compose run --rm scanner --config config.yaml
```

## CLI Options

- `--url`: Target WordPress URL (required)
- `--config`: YAML config file
- `--api-key`: WPScan API key
- `--crawl`: Enable multi-page crawling
- `--max-pages`: Max pages to crawl (default: 10)
- `--port-scan`: Enable port scanning
- `--ports`: Ports to scan (default: 80, 443, 3306, 22)
- `--output`: Output file
- `--format`: Output format (json/text, default: text)

## Libraries Used

- **requests**: HTTP requests and API interactions
- **beautifulsoup4**: HTML parsing for plugin/theme extraction
- **scrapy**: Web crawling for multi-page scanning
- **python-nmap**: Port scanning
- **pyyaml**: Configuration file parsing

   If you don't have an API key, omit the `-e WPSCAN_API_KEY` part. Vulnerability checks will be skipped.

## Output

The script will print:
- Number of plugins/themes found
- Number of users enumerated
- A report with users and vulnerable items

## Dependencies

- requests
- beautifulsoup4
- python-wordpress-api

## Notes

- User enumeration may fail if the REST API is disabled or protected.
- Vulnerability checks require a valid WPScan API key.
- Versions are extracted from query parameters; may not always be accurate.