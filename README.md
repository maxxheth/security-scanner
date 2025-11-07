# WordPress Security Scanner

A Dockerized Python script to audit WordPress sites for vulnerabilities in plugins/themes and enumerate users.

## Features

- **Initial Scan**: Extracts plugins and themes from the homepage using BeautifulSoup.
- **User Enumeration**: Fetches users via WordPress REST API.
- **Vulnerability Check**: Queries WPScan API for known vulnerabilities.
- **Reporting**: Outputs findings to console.

## Prerequisites

- Docker
- WPScan API Key (optional, for vulnerability checks). Sign up at https://wpscan.com/api/

## Usage

### Using Docker directly

1. Build the Docker image:
   ```bash
   docker build -t wp-scanner .
   ```

2. Run the scanner:
   ```bash
   docker run --rm -e WPSCAN_API_KEY=your_api_key_here wp-scanner https://example.com
   ```

### Using Docker Compose (recommended)

1. Set your WPScan API key in an environment variable (optional):
   ```bash
   export WPSCAN_API_KEY=your_api_key_here
   ```

2. Run the scanner as a one-off process:
   ```bash
   docker compose run --rm scanner https://example.com
   ```

   Replace `https://example.com` with the target WordPress site URL.

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