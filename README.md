ReverseRecon

ReverseRecon is a Python reverse reconnaissance tool designed to discover a company’s external attack surface by pivoting from organization name → ASN → IP ranges → reverse DNS → domains → subdomains → cloud infrastructure.

It focuses on infrastructure-driven reconnaissance, not classic wordlist-only enumeration.

This tool is especially useful for:

infrastructure mapping

external asset discovery

cloud exposure analysis

scoping for penetration tests and bug bounty programs

Features

Discover ASNs associated with a company name

Extract IP ranges from each ASN

Sample large CIDR blocks to avoid over-enumeration

Perform reverse DNS lookups on discovered IPs

Discover domains related to the organization

Filter false positives using:

domain validation

relevance heuristics

WHOIS ownership verification

Enumerate subdomains using:

crt.sh

common subdomain brute-force

optional external tools (subfinder, amass, dnsx)

Detect AWS EC2 infrastructure using official AWS IP ranges

Multi-threaded processing

JSON output

Optional plain-text output for domains and subdomains

How it works

The workflow is:

Find candidate main domains for the company

Discover ASNs related to the company name

Extract IP ranges from each ASN

Perform reverse DNS lookups on IP addresses

Validate and filter discovered domains

Enumerate subdomains for selected domains

Detect which IPs belong to AWS EC2 ranges

Export results

Installation
Requirements

Python 3.8+

System tools:

whois

dig

Python dependencies
pip install dnspython requests

Optional external tools

If present in your system, ReverseRecon will automatically use:

subfinder

amass

dnsx

They are optional. The tool works without them.

Usage
python3 reverse_recon.py -u <company>

Examples
python3 reverse_recon.py -u logitech

python3 reverse_recon.py -u microsoft -v -ra

python3 reverse_recon.py -u google -t 50 -o results.txt --max-ips 500

python3 reverse_recon.py -u amazon -v -ra -t 30 -o amazon_domains.txt --skip-ownership-check

Arguments
Option	Description
-u, --empresa	Company name or main domain to investigate
-v, --verbose	Verbose output
-ra, --random-agent	Use a random User-Agent for HTTP requests
-t, --threads	Number of worker threads (default: 20)
-o, --output	Output file with all discovered domains and subdomains
--max-ips	Maximum number of IPs sampled from ASN ranges (default: 1000)
--max-ips-reverse	Maximum IPs used for reverse DNS (default: 200)
--max-domains-sub	Maximum domains used for subdomain enumeration (default: 10)
--max-ips-ec2	Maximum IPs checked for AWS EC2 detection (default: 100)
--skip-ownership-check	Skip WHOIS ownership verification (faster but less accurate)
--aws-cache-ttl	AWS IP ranges cache TTL in seconds (default: 3600)
Output

At the end of execution the tool automatically generates:

recon_<company>.json


Example:

recon_google.json


The JSON file contains:

company

ASNs

IP addresses

domains

subdomains

detected EC2 instances

If -o is specified, a text file is also generated containing all discovered domains and subdomains.

AWS EC2 detection

ReverseRecon downloads and caches the official AWS IP ranges and detects whether discovered IPs belong to EC2 services.

Detected EC2 entries include:

IP address

AWS region

service name

network prefix

Domain ownership verification

When possible, the tool extracts the registrant organization from WHOIS data of the main domain and uses it to validate whether newly discovered domains belong to the same organization.

This helps reduce:

CDN noise

shared hosting artifacts

unrelated reverse DNS records

You can disable this verification with:

--skip-ownership-check

Notes and limitations

ASN discovery is based on public WHOIS data and the BGPView public API.

IP ranges are sampled to avoid processing extremely large networks.

WHOIS data quality depends on the registrar and registry.

Some subdomain tools (amass, subfinder, dnsx) may produce additional noise depending on their configuration.

Legal disclaimer

This tool is intended for authorized security testing, research and educational purposes only.

You are responsible for obtaining proper authorization before scanning or enumerating any infrastructure you do not own.

Author

Marcos Suárez
(Security researcher / pentester)
