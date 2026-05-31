
# IOC Enrichment Tool

A Python utility that extracts public IP addresses from log files and enriches them with threat intelligence data from AbuseIPDB and VirusTotal APIs.

## Features

- **IP Extraction**: Parses log files to identify and validate IPv4 addresses
- **Private IP Filtering**: Excludes private/internal IP ranges
- **Threat Intelligence**: Cross-references IPs against:
  - **AbuseIPDB**: Abuse confidence scores, country, ISP, report counts
  - **VirusTotal**: Malware detection counts from multiple vendors
- **Intelligent Verdicts**: Classifies IPs as malicious or clean based on configurable thresholds
- **Multiple Output Formats**: Generates both HTML and CSV reports
- **Rate Limiting**: Automatic throttling for VirusTotal API (4 requests/minute)
- **Flexible Input**: Command-line arguments for custom log file paths

## Requirements

- Python 3.x
- `requests`
- `python-dotenv`

## Setup

1. Install dependencies:
   ```bash
   pip install requests python-dotenv
   ```

2. Create `.env` file with API keys:
   ```
   ABUSEIPDB_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   ```

3. Place log files in `sample_logs/`

## Usage

```bash
python ioc_enrichment.py
```

Outputs an HTML report to `output/ioc_report.html`

### Command-Line Options

- `--log-file <path>`: Specify a custom log file path (default: `sample_logs/sample.log`)
- `--csv`: Output results as CSV in addition to HTML

### Examples

```bash
# Default: Extract from sample_logs/sample.log, generate HTML report
python ioc_enrichment.py

# Generate both HTML and CSV reports
python ioc_enrichment.py --csv

# Process a custom log file
python ioc_enrichment.py --log-file /path/to/access.log

# Custom log file with CSV output
python ioc_enrichment.py --log-file /path/to/access.log --csv

# View help
python ioc_enrichment.py --help
```

### Output Files

- **HTML**: `output/ioc_report.html` (color-coded table with styling)
- **CSV**: `output/ioc_report.csv` (machine-readable format)

## Verdict Logic

- **Malicious (IOC)**: AbuseIPDB score > 25 OR VirusTotal detections > 3
- **Clean**: Otherwise

## Rate Limiting

The tool includes automatic rate limiting for VirusTotal API calls:
- **VT Free Tier**: 4 requests per minute (15 second delay between calls)
- **Automatic**: No configuration needed—throttling is built-in
- **Use Case**: Safe to run against large log files without hitting API rate limits
