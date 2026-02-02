# Nth Party Finder (nthpartyfinder)

[![Build Status](https://github.com/your-org/nthpartyfinder/workflows/Build%20and%20Test/badge.svg)](https://github.com/your-org/nthpartyfinder/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, cross-platform command line tool for identifying Nth party vendor relationships through DNS analysis. Built in Rust for security, performance, and memory safety.

## Problem Statement

Security GRC teams responsible for third-party cyber risk management struggle to understand the full scope of their vendor risk surface. Much of this risk is inherited through vendor-to-vendor relationships that are complex to identify, map, and assess. Without a holistic picture of all vendor relationships to the Nth degree (beyond just 4th and 5th party), Security GRC teams cannot successfully understand which third parties pose the greatest risk.

## Features

🔍 **Comprehensive Analysis**: Analyzes DNS TXT records (SPF, domain verification) to identify vendor relationships

🌐 **Cross-Platform**: Runs on Windows, macOS, and Linux with optimized performance

🔄 **Recursive Discovery**: Configurable depth analysis or automatic discovery until common denominators

📊 **Multiple Export Formats**: CSV (default) and JSON output with detailed relationship mapping

⚡ **High Performance**: Built in Rust with async processing and intelligent caching

🛡️ **Security-First**: Memory-safe implementation with comprehensive error handling

🧠 **Embedded NER**: Optional GLiNER model for intelligent organization name extraction (offline capable)

## Installation

### Option 1: Docker (Recommended)

Pull the pre-built image with embedded NER:

```bash
docker pull ghcr.io/your-org/nthpartyfinder:latest
```

Or build locally:

```bash
docker build -t nthpartyfinder .
```

Run analysis:

```bash
docker run -v $(pwd)/output:/output nthpartyfinder -d example.com -r 2 -f json -o /output/results
```

### Option 2: Pre-built Binaries

Download from [Releases](https://github.com/your-org/nthpartyfinder/releases):

- **Full version** (`nthpartyfinder-full`): Includes embedded NER (~150MB)
- **Slim version** (`nthpartyfinder`): No NER, smaller size (~15MB)

Platform-specific binaries:

- **Windows**: `nthpartyfinder-windows-x86_64.exe`
- **macOS (Intel)**: `nthpartyfinder-macos-x86_64`
- **macOS (Apple Silicon)**: `nthpartyfinder-macos-aarch64`
- **Linux**: `nthpartyfinder-linux-x86_64`

### Option 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/nthpartyfinder.git
cd nthpartyfinder

# Download model files (required for default build)
./scripts/download-model.sh  # or .ps1 on Windows

# Build with embedded NER (default)
cargo build --release

# Build WITHOUT NER (smaller binary, ~15MB vs ~175MB)
cargo build --release --no-default-features
```

#### Windows-Specific Setup for NER

On Windows, the ONNX Runtime DLL must be available at runtime. The build uses dynamic loading to avoid linker conflicts with system DLLs:

```powershell
# Download ONNX Runtime DLL
.\scripts\download-onnxruntime.ps1

# The DLL is automatically found if:
# 1. It's in the same directory as the executable
# 2. It's in the onnxruntime/ subdirectory
# 3. ORT_DYLIB_PATH environment variable is set
```

Alternatively, set the environment variable:

```powershell
$env:ORT_DYLIB_PATH = "C:\path\to\onnxruntime.dll"
```

### Prerequisites

- **WHOIS command**: Most systems have this installed by default
  - **Ubuntu/Debian**: `sudo apt-get install whois`
  - **macOS**: `brew install whois`
  - **Windows**: Download from SysInternals or use WSL

## Usage

### Basic Usage

```bash
# Analyze a domain with default settings (CSV output)
nthpartyfinder --domain example.com

# Specify output format and file
nthpartyfinder --domain example.com --output-format json --output results.json

# Limit recursion depth
nthpartyfinder --domain example.com --depth 3
```

### Command Line Options

```
Usage: nthpartyfinder [OPTIONS] --domain <DOMAIN>

Options:
  -d, --domain <DOMAIN>          Domain name to analyze for Nth party relationships
  -r, --depth <DEPTH>            Maximum recursion depth (if not specified, recurses until no more vendors found)
  -f, --output-format <FORMAT>   Output format: 'csv', 'json', 'markdown', or 'html' [default: csv]
  -o, --output <FILE>            Output filename [default: nth_parties]
      --output-dir <DIR>         Output directory for results (default: Desktop)
  -j, --parallel-jobs <N>        Number of parallel jobs [default: 10]
  -v, --verbose                  Verbose logging (-v for INFO, -vv for DEBUG)
      --init                     Create default configuration file
  -h, --help                     Print help
  -V, --version                  Print version

Discovery Options:
      --enable-subprocessor-analysis    Enable subprocessor web page analysis
      --disable-subprocessor-analysis   Disable subprocessor analysis
      --enable-subdomain-discovery      Enable subdomain discovery (requires subfinder)
      --disable-subdomain-discovery     Disable subdomain discovery
      --enable-saas-tenant-discovery    Enable SaaS tenant discovery
      --disable-saas-tenant-discovery   Disable SaaS tenant discovery
      --enable-ct-discovery             Enable Certificate Transparency log discovery
      --disable-ct-discovery            Disable CT log discovery
      --enable-slm                      Enable NER organization extraction
      --disable-slm                     Disable NER extraction
      --enable-web-org                  Enable web page organization extraction
      --disable-web-org                 Disable web page org extraction
      --subfinder-path <PATH>           Path to subfinder binary

Rate Limiting Options:
      --dns-rate-limit <QPS>            Maximum DNS queries per second
      --http-rate-limit <RPS>           Maximum HTTP requests per second per domain
      --backoff-strategy <STRATEGY>     Backoff strategy: "linear" or "exponential"
      --max-retries <COUNT>             Maximum retry attempts
      --whois-concurrency <N>           Maximum concurrent WHOIS lookups
```

See [Configuration Guide](docs/configuration.md) for detailed configuration options.

### Examples

#### Example 1: Basic Analysis
```bash
nthpartyfinder --domain github.com
```

Output:
```
=== Analysis Summary ===
Total vendor relationships found: 12
Maximum depth reached: 3 layers
Unique vendor domains: 8
Unique vendor organizations: 6
  Layer 1 vendors: 4
  Layer 2 vendors: 5
  Layer 3 vendors: 3
========================

Analysis complete. Results exported to: nth_parties.csv
```

#### Example 2: Limited Depth Analysis
```bash
nthpartyfinder --domain company.com --depth 2 --output-format json --output company_vendors.json
```

#### Example 3: Comprehensive Analysis
```bash
nthpartyfinder --domain startup.io --verbose
```

## Output Format

### CSV Output

The CSV output includes the following columns:

| Column | Description |
|--------|-------------|
| Nth Party Domain | The vendor domain identified |
| Nth Party Organization | Organization name from WHOIS lookup |
| Nth Party Layer | Relationship depth (1st, 2nd, 3rd party, etc.) |
| Nth Party Customer Domain | The domain that references this vendor |
| Nth Party Customer Organization | Customer organization name |
| Nth Party Record | The actual DNS record containing the reference |
| Nth Party Record Type | Type of DNS record (TXT, SPF, etc.) |

### JSON Output

The JSON output provides the same data in a structured format with additional summary information:

```json
{
  "summary": {
    "total_relationships": 12,
    "max_depth": 3,
    "unique_domains": 8,
    "unique_organizations": 6
  },
  "relationships": [
    {
      "nth_party_domain": "vendor.com",
      "nth_party_organization": "Vendor Inc.",
      "nth_party_layer": 1,
      "nth_party_customer_domain": "example.com",
      "nth_party_customer_organization": "Example Corp",
      "nth_party_record": "vendor.com",
      "nth_party_record_type": "TXT"
    }
  ]
}
```

## Configuration

nthpartyfinder uses a TOML configuration file for persistent settings. CLI arguments override config file values.

### Quick Setup

```bash
# Create default configuration file
nthpartyfinder --init

# This creates ./config/nthpartyfinder.toml
```

### Configuration File Location

```
./config/nthpartyfinder.toml
```

### Key Configuration Sections

| Section | Description |
|---------|-------------|
| `[http]` | HTTP client settings (user agent, timeouts) |
| `[dns]` | DNS servers (DoH and traditional) |
| `[patterns]` | Vendor detection patterns and mappings |
| `[analysis]` | Resource management (concurrency, strategies) |
| `[discovery]` | Feature toggles (subprocessor, subdomain, NER) |
| `[rate_limits]` | Request rate limiting and backoff |

### Example: Override Config via CLI

```bash
# Use higher rate limits for this run only
nthpartyfinder --domain example.com --dns-rate-limit 100 --http-rate-limit 20

# Disable features for quick scan
nthpartyfinder --domain example.com --disable-subprocessor-analysis --disable-slm
```

For detailed configuration options, see the [Configuration Guide](docs/configuration.md).

## How It Works

1. **DNS Analysis**: Queries TXT records for the target domain
2. **Vendor Extraction**: Parses SPF records and domain verification strings
3. **Organization Lookup**: Uses WHOIS to identify organization names
4. **Recursive Discovery**: Repeats the process for each discovered vendor
5. **Termination**: Stops at configured depth or common denominators
6. **Export**: Generates comprehensive relationship mapping

### Common Denominators

The tool automatically identifies common infrastructure providers to prevent infinite recursion:

- Amazon Web Services (AWS)
- Microsoft Azure/Office 365
- Google Cloud Platform
- Cloudflare
- Fastly
- Akamai

### Embedded NER Organization Extraction

The default build includes a GLiNER model for intelligent organization name extraction.
This provides several advantages:

- **No External Services**: Works completely offline without API dependencies
- **Improved Accuracy**: Machine learning-based extraction identifies organization names more reliably than regex patterns
- **Subprocessor Detection**: Better identification of vendor names from privacy policies and subprocessor lists

The NER model is approximately 175MB and is embedded directly in the binary.
To build a slim version without NER, use `cargo build --release --no-default-features`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/nthpartyfinder.git
cd nthpartyfinder

# Run tests
cargo test

# Run with verbose logging
cargo run -- --domain example.com --verbose

# Build release version
cargo build --release
```

## Future Enhancements

- **Website Analysis**: DOM and XHR request analysis for hosted content
- **Additional DNS Records**: SOA, MX, CNAME analysis
- **Subdomain Discovery**: Integration with tools like subfinder
- **Risk Scoring**: Automated vendor risk assessment
- **API Integration**: REST API for programmatic access
- **Visualization**: Graph-based relationship visualization

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

This tool is designed for legitimate security and GRC purposes only. Please use responsibly and in accordance with applicable laws and regulations.

## Support

- 📖 Documentation: [Wiki](https://github.com/your-org/nthpartyfinder/wiki)
- 🐛 Bug Reports: [Issues](https://github.com/your-org/nthpartyfinder/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/your-org/nthpartyfinder/discussions)