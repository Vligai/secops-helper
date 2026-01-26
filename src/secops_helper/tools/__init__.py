"""
SecOps Helper Tools - Security operations toolset

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
    'eml_parser',
    'ioc_extractor',
    'hash_lookup',
    'domain_ip_intel',
    'log_analyzer',
    'pcap_analyzer',
    'url_analyzer',
    'yara_scanner',
    'cert_analyzer',
    'deobfuscator',
    'threat_feed_aggregator',
    'file_carver',
]


def get_tool_registry():
    """
    Get registry of all available tools with their metadata.

    Returns:
        Dict mapping tool IDs to their metadata
    """
    return {
        'eml': {
            'name': 'EML Parser',
            'module': 'secops_helper.tools.eml_parser',
            'category': 'Email Analysis',
            'description': 'Parse and analyze email files (.eml) with attachment hashing and header analysis',
            'keywords': ['email', 'eml', 'phishing', 'attachment', 'header', 'spf', 'dkim', 'dmarc'],
        },
        'ioc': {
            'name': 'IOC Extractor',
            'module': 'secops_helper.tools.ioc_extractor',
            'category': 'Threat Intelligence',
            'description': 'Extract indicators of compromise (IPs, domains, URLs, hashes, CVEs) from text',
            'keywords': ['ioc', 'indicator', 'ip', 'domain', 'url', 'hash', 'cve', 'extract'],
        },
        'hash': {
            'name': 'Hash Lookup',
            'module': 'secops_helper.tools.hash_lookup',
            'category': 'Threat Intelligence',
            'description': 'Look up file hashes against VirusTotal and MalwareBazaar',
            'keywords': ['hash', 'md5', 'sha1', 'sha256', 'virustotal', 'malware', 'threat'],
        },
        'intel': {
            'name': 'Domain/IP Intelligence',
            'module': 'secops_helper.tools.domain_ip_intel',
            'category': 'Threat Intelligence',
            'description': 'Analyze domains and IP addresses with threat intelligence and DNS resolution',
            'keywords': ['domain', 'ip', 'dns', 'whois', 'reputation', 'threat', 'intelligence'],
        },
        'log': {
            'name': 'Log Analyzer',
            'module': 'secops_helper.tools.log_analyzer',
            'category': 'Log Analysis',
            'description': 'Analyze Apache, Nginx, and syslog files for security threats',
            'keywords': ['log', 'apache', 'nginx', 'syslog', 'attack', 'web', 'security'],
        },
        'pcap': {
            'name': 'PCAP Analyzer',
            'module': 'secops_helper.tools.pcap_analyzer',
            'category': 'Network Analysis',
            'description': 'Analyze network traffic captures for threats and anomalies',
            'keywords': ['pcap', 'network', 'traffic', 'packet', 'dns', 'http', 'scan'],
        },
        'url': {
            'name': 'URL Analyzer',
            'module': 'secops_helper.tools.url_analyzer',
            'category': 'Threat Intelligence',
            'description': 'Analyze URLs for threats, phishing, and malware',
            'keywords': ['url', 'link', 'phishing', 'malware', 'suspicious', 'threat'],
        },
        'yara': {
            'name': 'YARA Scanner',
            'module': 'secops_helper.tools.yara_scanner',
            'category': 'Malware Analysis',
            'description': 'Scan files and directories with YARA malware detection rules',
            'keywords': ['yara', 'malware', 'scan', 'signature', 'rule', 'detection'],
        },
        'cert': {
            'name': 'Certificate Analyzer',
            'module': 'secops_helper.tools.cert_analyzer',
            'category': 'SSL/TLS Analysis',
            'description': 'Analyze SSL/TLS certificates for security issues and phishing',
            'keywords': ['certificate', 'ssl', 'tls', 'https', 'x509', 'phishing', 'crypto'],
        },
        'deobfuscate': {
            'name': 'Script Deobfuscator',
            'module': 'secops_helper.tools.deobfuscator',
            'category': 'Malware Analysis',
            'description': 'Deobfuscate PowerShell, JavaScript, VBScript, and other malicious scripts',
            'keywords': ['deobfuscate', 'powershell', 'javascript', 'vbscript', 'decode', 'base64'],
        },
        'threatfeed': {
            'name': 'Threat Feed Aggregator',
            'module': 'secops_helper.tools.threat_feed_aggregator',
            'category': 'Threat Intelligence',
            'description': 'Aggregate and manage threat intelligence feeds from multiple sources',
            'keywords': ['threat', 'feed', 'ioc', 'aggregator', 'threatfox', 'urlhaus'],
        },
        'carve': {
            'name': 'File Carver',
            'module': 'secops_helper.tools.file_carver',
            'category': 'Forensics',
            'description': 'Extract embedded files from disk images, memory dumps, and binary files',
            'keywords': ['carve', 'forensics', 'extract', 'file', 'disk', 'memory', 'dump'],
        }
    }
