"""
vlair Tools - Security operations toolset

Available tools:
- eml_parser: Email analysis and parsing
- ioc_extractor: IOC extraction from text
- hash_lookup: Hash reputation lookup
- domain_ip_intel: Domain/IP intelligence
- log_analyzer: Log file analysis
- pcap_analyzer: Network traffic analysis
- url_analyzer: URL threat analysis
- yara_scanner: YARA malware scanning
- cert_analyzer: SSL/TLS certificate analysis
- deobfuscator: Script deobfuscation
- threat_feed_aggregator: Threat intelligence aggregation
- file_carver: File carving and extraction
"""

# Import main classes from each tool for easy access
# These are imported lazily when needed to avoid heavy startup costs

__all__ = [
    # Tool module names
    "eml_parser",
    "ioc_extractor",
    "hash_lookup",
    "domain_ip_intel",
    "log_analyzer",
    "pcap_analyzer",
    "url_analyzer",
    "yara_scanner",
    "cert_analyzer",
    "deobfuscator",
    "threat_feed_aggregator",
    "file_carver",
]


def get_tool_registry():
    """
    Get registry of all available tools with their metadata.

    Returns:
        Dict mapping tool IDs to their metadata including:
        - name: Display name
        - module: Python module path
        - category: Tool category for grouping
        - description: Brief description
        - keywords: Search keywords
        - examples: Usage examples
        - requires_api: List of API keys needed
    """
    return {
        "eml": {
            "name": "EML Parser",
            "module": "vlair.tools.eml_parser",
            "category": "Email Analysis",
            "description": "Parse and analyze email files (.eml) with attachment hashing and header analysis",
            "keywords": [
                "email",
                "eml",
                "phishing",
                "attachment",
                "header",
                "spf",
                "dkim",
                "dmarc",
            ],
            "examples": [
                "vlair eml suspicious.eml --vt",
                "vlair eml phishing.eml --output report.json",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "ioc": {
            "name": "IOC Extractor",
            "module": "vlair.tools.ioc_extractor",
            "category": "Threat Intelligence",
            "description": "Extract indicators of compromise (IPs, domains, URLs, hashes, CVEs) from text",
            "keywords": ["ioc", "indicator", "ip", "domain", "url", "hash", "cve", "extract"],
            "examples": [
                "vlair ioc threat_report.txt",
                "vlair ioc --file report.txt --format csv --defang",
            ],
            "requires_api": [],
        },
        "hash": {
            "name": "Hash Lookup",
            "module": "vlair.tools.hash_lookup",
            "category": "Threat Intelligence",
            "description": "Look up file hashes against VirusTotal and MalwareBazaar",
            "keywords": ["hash", "md5", "sha1", "sha256", "virustotal", "malware", "threat"],
            "examples": [
                "vlair hash 44d88612fea8a8f36de82e1278abb02f",
                "vlair hash --file hashes.txt --verbose",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "intel": {
            "name": "Domain/IP Intelligence",
            "module": "vlair.tools.domain_ip_intel",
            "category": "Threat Intelligence",
            "description": "Analyze domains and IP addresses with threat intelligence and DNS resolution",
            "keywords": ["domain", "ip", "dns", "whois", "reputation", "threat", "intelligence"],
            "examples": ["vlair intel malicious.com", "vlair intel 1.2.3.4 --verbose"],
            "requires_api": ["VT_API_KEY", "ABUSEIPDB_KEY (optional)"],
        },
        "log": {
            "name": "Log Analyzer",
            "module": "vlair.tools.log_analyzer",
            "category": "Log Analysis",
            "description": "Analyze Apache, Nginx, and syslog files for security threats",
            "keywords": ["log", "apache", "nginx", "syslog", "attack", "web", "security"],
            "examples": [
                "vlair log /var/log/apache2/access.log",
                "vlair log nginx.log --type nginx --format txt",
            ],
            "requires_api": [],
        },
        "pcap": {
            "name": "PCAP Analyzer",
            "module": "vlair.tools.pcap_analyzer",
            "category": "Network Analysis",
            "description": "Analyze network traffic captures for threats and anomalies",
            "keywords": ["pcap", "network", "traffic", "packet", "dns", "http", "scan"],
            "examples": [
                "vlair pcap capture.pcap",
                "vlair pcap traffic.pcapng --verbose --output analysis.json",
            ],
            "requires_api": [],
        },
        "url": {
            "name": "URL Analyzer",
            "module": "vlair.tools.url_analyzer",
            "category": "Threat Intelligence",
            "description": "Analyze URLs for threats, phishing, and malware",
            "keywords": ["url", "link", "phishing", "malware", "suspicious", "threat"],
            "examples": [
                'vlair url "http://suspicious-site.com"',
                "vlair url --file urls.txt --format json",
            ],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "yara": {
            "name": "YARA Scanner",
            "module": "vlair.tools.yara_scanner",
            "category": "Malware Analysis",
            "description": "Scan files and directories with YARA malware detection rules",
            "keywords": ["yara", "malware", "scan", "signature", "rule", "detection"],
            "examples": [
                "vlair yara scan /samples/ --rules ./rules/",
                "vlair yara scan malware.exe --rules custom.yar",
            ],
            "requires_api": [],
        },
        "cert": {
            "name": "Certificate Analyzer",
            "module": "vlair.tools.cert_analyzer",
            "category": "SSL/TLS Analysis",
            "description": "Analyze SSL/TLS certificates for security issues and phishing",
            "keywords": ["certificate", "ssl", "tls", "https", "x509", "phishing", "crypto"],
            "examples": [
                "vlair cert https://example.com",
                "vlair cert --file cert.pem --hostname example.com",
            ],
            "requires_api": [],
        },
        "deobfuscate": {
            "name": "Script Deobfuscator",
            "module": "vlair.tools.deobfuscator",
            "category": "Malware Analysis",
            "description": "Deobfuscate PowerShell, JavaScript, VBScript, and other malicious scripts",
            "keywords": ["deobfuscate", "powershell", "javascript", "vbscript", "decode", "base64"],
            "examples": [
                "vlair deobfuscate malware.js --extract-iocs",
                "vlair deobfuscate script.ps1 --language powershell",
            ],
            "requires_api": [],
        },
        "threatfeed": {
            "name": "Threat Feed Aggregator",
            "module": "vlair.tools.threat_feed_aggregator",
            "category": "Threat Intelligence",
            "description": "Aggregate and manage threat intelligence feeds from multiple sources",
            "keywords": ["threat", "feed", "ioc", "aggregator", "threatfox", "urlhaus"],
            "examples": [
                "vlair threatfeed update --source all",
                "vlair threatfeed search --type domain --confidence 80",
            ],
            "requires_api": [],
        },
        "carve": {
            "name": "File Carver",
            "module": "vlair.tools.file_carver",
            "category": "Forensics",
            "description": "Extract embedded files from disk images, memory dumps, and binary files",
            "keywords": ["carve", "forensics", "extract", "file", "disk", "memory", "dump"],
            "examples": [
                "vlair carve --image disk.dd --output /carved/",
                "vlair carve --image memdump.raw --types exe,dll,pdf",
            ],
            "requires_api": [],
        },
    }
