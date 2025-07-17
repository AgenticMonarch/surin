# SURIN - Subdomain Utility for Rapid Identification and Naming

SURIN is an advanced command-line tool for subdomain discovery, designed for security professionals, penetration testers, and researchers. It leverages multiple discovery methods to provide comprehensive subdomain reconnaissance capabilities.

## Features

- **Multiple Discovery Methods**:
  - DNS Enumeration with 60+ common subdomain patterns
  - Certificate Transparency logs (via crt.sh)
  - HackerTarget API
  - ThreatCrowd API
  - VirusTotal API (requires API key)

- **Concurrent Processing**:
  - Parallel execution of discovery methods
  - Configurable concurrency levels
  - Rate limiting and backoff strategies

- **Result Enrichment**:
  - IP resolution for discovered subdomains
  - Public/private IP detection
  - HTTP/HTTPS status checking
  - Open port detection

- **Flexible Output**:
  - Text, JSON, and CSV output formats
  - Detailed subdomain information
  - Comprehensive summary statistics

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Install from PyPI

```bash
pip install surin
```

### Install from Source

```bash
# Clone the repository
git clone https://github.com/AgenticMonarch/surin.git
cd surin

# Recommended installation method
python setup.py install

# Verify installation
surin --version
```

### Troubleshooting Installation

If you encounter any issues during installation:

1. Ensure you have the latest version of pip and setuptools:
   ```bash
   pip install --upgrade pip setuptools wheel
   ```

2. If you're using a virtual environment (recommended), make sure it's activated:
   ```bash
   # Create a virtual environment
   python -m venv venv
   
   # Activate on macOS/Linux
   source venv/bin/activate
   
   # Activate on Windows
   venv\Scripts\activate
   ```

3. Try the direct installation method:
   ```bash
   python setup.py install
   ```

4. If you get errors about missing dependencies, install them manually:
   ```bash
   pip install dnspython requests tqdm
   ```

5. Check that the package is installed correctly:
   ```bash
   pip list | grep surin
   ```

6. If all else fails, you can run the tool directly without installation:
   ```bash
   python -m surin.cli example.com
   ```

## Usage

### Basic Usage

```bash
surin example.com
```

This will run all available discovery methods against the domain `example.com` in fast scan mode and display the results in text format. Fast scan mode is the default and only shows subdomain names without additional checks.

### Selecting Specific Methods

```bash
surin example.com --methods dns,crt
```

This will only run the DNS enumeration and Certificate Transparency methods.

### Output Formats

```bash
# Output as JSON
surin example.com --output json

# Output as CSV
surin example.com --output csv

# Save output to a file
surin example.com --output-file results.txt
```

### API Keys

Some discovery methods require API keys:

```bash
# Use VirusTotal API
surin example.com --virustotal-key YOUR_API_KEY
```

### Concurrency Control

```bash
# Set maximum concurrent operations
surin example.com --concurrency 20
```

### Verbosity Options

```bash
# Enable verbose output
surin example.com -v

# Suppress all non-error output
surin example.com -q
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain to discover subdomains for |
| `--methods` | Comma-separated list of discovery methods to use (default: all) |
| `--scan-mode` | Scan mode: fast or deep (default: fast) |
| `--show-ip` | Show IP addresses in fast scan mode (default: False) |
| `--output` | Output format: text, json, or csv (default: text) |
| `--output-file` | Write output to file instead of stdout |
| `--concurrency` | Maximum number of concurrent operations (default: 10) |
| `--virustotal-key` | VirusTotal API key |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress all non-error output |
| `--version` | Show version information and exit |

## Available Discovery Methods

| Method | Description | API Key Required |
|--------|-------------|-----------------|
| `dns` | DNS enumeration using common subdomain patterns | No |
| `crt` | Certificate Transparency logs via crt.sh | No |
| `hackertarget` | HackerTarget API | No |
| `threatcrowd` | ThreatCrowd API | No |
| `virustotal` | VirusTotal API | Yes |

## Output Formats

### Text Format

The text output includes:
- Subdomains grouped by discovery method
- IP addresses with public/private status
- HTTP/HTTPS status codes
- Open ports and detected services
- Summary statistics

Example:
```
SURIN Subdomain Discovery Results
========================================

Method: dns
----------------------------------------
www.example.com
  IP: 93.184.216.34 (public)
  HTTP: 200
  HTTPS: 200
  Discovered by: dns

mail.example.com
  IP: 93.184.216.34 (public)
  HTTP: 301
  HTTPS: 200
  Discovered by: dns

...

Summary
----------------------------------------
Total subdomains: 12
Unique IP addresses: 3
Public IPs: 3
Private IPs: 0

Discovery method statistics:
  dns: 8 subdomains
  crt: 10 subdomains
```

### JSON Format

The JSON output provides a structured representation of all discovered subdomains and statistics.

### CSV Format

The CSV output includes one row per subdomain with columns for all relevant information, suitable for importing into spreadsheets or databases.

## Scan Modes

SURIN supports two scanning modes:

### Fast Scan Mode (Default)

Fast scan mode only discovers subdomain names without performing additional checks like IP resolution, HTTP status checks, or port scanning. This mode is significantly faster and is ideal for initial reconnaissance.

```bash
# Fast scan is the default
surin example.com

# Explicitly specify fast scan mode
surin example.com --scan-mode fast
```

You can optionally show IP addresses in fast scan mode without performing other checks:

```bash
# Show IP addresses in fast scan mode
surin example.com --show-ip
```

### Deep Scan Mode

Deep scan mode performs comprehensive checks on discovered subdomains, including:
- IP resolution
- Public/private IP detection
- HTTP/HTTPS status checking
- Open port detection
- Service identification

```bash
# Run deep scan
surin example.com --scan-mode deep
```

Deep scan provides more information but takes significantly longer to complete.

## Examples

### Basic Reconnaissance

```bash
# Simple subdomain discovery (fast scan)
surin example.com

# Deep scan with all available information
surin example.com --scan-mode deep
```

### Targeted Reconnaissance with Specific Methods

```bash
# Use only DNS and Certificate Transparency methods
surin example.com --methods dns,crt --output json --output-file example-recon.json

# Use all methods except VirusTotal
surin example.com --methods dns,crt,hackertarget,threatcrowd
```

### Verbose Mode with High Concurrency

```bash
# Increase concurrency for faster scanning with verbose output
surin example.com -v --concurrency 20

# Save results to CSV file with high concurrency
surin example.com --concurrency 30 --output csv --output-file example-domains.csv
```

### Advanced Usage

```bash
# Combine multiple options
surin example.com --methods dns,crt --concurrency 15 -v --output-file results.txt

# Use VirusTotal API with specific methods
surin example.com --methods dns,virustotal --virustotal-key YOUR_API_KEY --output json
```

## Troubleshooting

### Common Issues

1. **Rate Limiting**: If you encounter API rate limiting, especially with HackerTarget or VirusTotal:
   ```bash
   # Reduce concurrency
   surin example.com --concurrency 5
   ```

2. **DNS Resolution Failures**: If DNS resolution is failing:
   ```bash
   # Use only Certificate Transparency logs
   surin example.com --methods crt
   ```

3. **Slow Performance**: For large domains with many subdomains:
   ```bash
   # Increase concurrency but limit methods
   surin example.com --methods dns,crt --concurrency 30
   ```

4. **Memory Issues**: If you encounter memory problems with large results:
   ```bash
   # Output directly to file instead of keeping in memory
   surin example.com --output-file results.txt
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.