#!/usr/bin/env python3
"""
Hash Lookup - Query file hashes against threat intelligence sources
Supports VirusTotal, MalwareBazaar, and local caching
"""

import re
import sys
import json
import argparse
import os
import sqlite3
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class HashValidator:
    """Validate and identify hash types"""

    HASH_PATTERNS = {
        'md5': (r'^[a-fA-F0-9]{32}$', 32),
        'sha1': (r'^[a-fA-F0-9]{40}$', 40),
        'sha256': (r'^[a-fA-F0-9]{64}$', 64),
        'sha512': (r'^[a-fA-F0-9]{128}$', 128),
    }

    @staticmethod
    def validate(hash_str: str) -> Tuple[bool, Optional[str]]:
        """Validate hash and return (is_valid, hash_type)"""
        hash_str = hash_str.strip().lower()

        for hash_type, (pattern, length) in HashValidator.HASH_PATTERNS.items():
            if len(hash_str) == length and re.match(pattern, hash_str):
                return True, hash_type

        return False, None

    @staticmethod
    def normalize(hash_str: str) -> str:
        """Normalize hash string"""
        return hash_str.strip().lower()


class CacheManager:
    """Manage hash lookup cache using SQLite"""

    def __init__(self, cache_path: str = None, ttl: int = 86400):
        self.cache_path = cache_path or os.path.expanduser('~/.hashlookup_cache.db')
        self.ttl = ttl  # Time-to-live in seconds
        self._init_db()
        self.hits = 0
        self.misses = 0

    def _init_db(self):
        """Initialize SQLite database"""
        Path(self.cache_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hash_cache (
                hash TEXT PRIMARY KEY,
                hash_type TEXT,
                result TEXT,
                timestamp INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    def get(self, hash_value: str) -> Optional[Dict]:
        """Retrieve cached result"""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute(
            'SELECT result, timestamp FROM hash_cache WHERE hash = ?',
            (hash_value,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            result_json, timestamp = row
            # Check if cache entry is still valid
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                return json.loads(result_json)
            else:
                # Cache expired, remove it
                self._delete(hash_value)

        self.misses += 1
        return None

    def set(self, hash_value: str, hash_type: str, result: Dict):
        """Store result in cache"""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO hash_cache (hash, hash_type, result, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (hash_value, hash_type, json.dumps(result), int(time.time())))

        conn.commit()
        conn.close()

    def _delete(self, hash_value: str):
        """Delete cache entry"""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM hash_cache WHERE hash = ?', (hash_value,))
        conn.commit()
        conn.close()

    def stats(self) -> Dict:
        """Return cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'total_queries': total,
            'hit_rate_percent': round(hit_rate, 2)
        }


class RateLimiter:
    """Simple rate limiter"""

    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.interval = 60.0 / requests_per_minute  # seconds between requests
        self.last_request = 0

    def wait(self):
        """Wait if necessary to respect rate limit"""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_request = time.time()


class VirusTotalAPI:
    """VirusTotal API v3 integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'

    def lookup_hash(self, hash_value: str) -> Optional[Dict]:
        """Lookup hash on VirusTotal"""
        if not self.api_key:
            return None

        url = f'{self.base_url}/files/{hash_value}'
        headers = {'x-apikey': self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                attrs = data['data']['attributes']
                stats = attrs['last_analysis_stats']

                return {
                    'source': 'virustotal',
                    'verdict': self._classify_verdict(stats),
                    'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'malware_names': self._extract_malware_names(attrs.get('last_analysis_results', {})),
                    'first_seen': attrs.get('first_submission_date'),
                    'last_seen': attrs.get('last_submission_date'),
                    'permalink': f'https://www.virustotal.com/gui/file/{hash_value}',
                }
            elif response.status_code == 404:
                return {
                    'source': 'virustotal',
                    'verdict': 'unknown',
                    'error': 'Hash not found'
                }
            else:
                return {
                    'source': 'virustotal',
                    'verdict': 'error',
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            return {
                'source': 'virustotal',
                'verdict': 'error',
                'error': str(e)
            }

    def _classify_verdict(self, stats: Dict) -> str:
        """Classify verdict based on detection stats"""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        if malicious >= 5:
            return 'malicious'
        elif malicious > 0 or suspicious > 0:
            return 'suspicious'
        else:
            return 'clean'

    def _extract_malware_names(self, results: Dict) -> List[str]:
        """Extract malware family names from results"""
        names = set()
        for engine, data in results.items():
            if data.get('category') in ['malicious', 'suspicious']:
                result = data.get('result', '')
                if result:
                    names.add(result)
        return sorted(list(names))[:10]  # Limit to top 10


class MalwareBazaarAPI:
    """MalwareBazaar API integration"""

    BASE_URL = 'https://mb-api.abuse.ch/api/v1/'

    def lookup_hash(self, hash_value: str) -> Optional[Dict]:
        """Lookup hash on MalwareBazaar"""
        try:
            data = {
                'query': 'get_info',
                'hash': hash_value
            }

            response = requests.post(self.BASE_URL, data=data, timeout=15)

            if response.status_code == 200:
                result = response.json()

                if result.get('query_status') == 'ok':
                    info = result['data'][0]
                    return {
                        'source': 'malwarebazaar',
                        'verdict': 'malicious',
                        'signature': info.get('signature'),
                        'file_type': info.get('file_type'),
                        'file_name': info.get('file_name'),
                        'tags': info.get('tags', []),
                        'first_seen': info.get('first_seen'),
                        'permalink': f"https://bazaar.abuse.ch/sample/{hash_value}/"
                    }
                elif result.get('query_status') == 'hash_not_found':
                    return {
                        'source': 'malwarebazaar',
                        'verdict': 'unknown',
                        'error': 'Hash not found'
                    }

        except Exception as e:
            return {
                'source': 'malwarebazaar',
                'verdict': 'error',
                'error': str(e)
            }

        return None


class HashLookup:
    """Main hash lookup orchestrator"""

    def __init__(self, cache_enabled=True, cache_ttl=86400, rate_limit=4, verbose=False):
        self.cache = CacheManager(ttl=cache_ttl) if cache_enabled else None
        self.rate_limiter = RateLimiter(rate_limit)
        self.verbose = verbose

        # Initialize APIs
        vt_key = os.getenv('VT_API_KEY')
        self.vt_api = VirusTotalAPI(vt_key) if vt_key else None
        self.mb_api = MalwareBazaarAPI()

    def lookup(self, hash_value: str) -> Dict:
        """Lookup a single hash"""
        # Validate hash
        is_valid, hash_type = HashValidator.validate(hash_value)
        if not is_valid:
            return {
                'hash': hash_value,
                'error': 'Invalid hash format'
            }

        hash_value = HashValidator.normalize(hash_value)

        # Check cache
        if self.cache:
            cached = self.cache.get(hash_value)
            if cached:
                if self.verbose:
                    print(f"[Cache hit] {hash_value}", file=sys.stderr)
                cached['cached'] = True
                return cached

        if self.verbose:
            print(f"[Querying] {hash_value}", file=sys.stderr)

        # Query sources
        result = {
            'hash': hash_value,
            'hash_type': hash_type,
            'verdict': 'unknown',
            'risk_level': 'unknown',
            'sources': {},
            'cached': False
        }

        # Query VirusTotal
        if self.vt_api:
            self.rate_limiter.wait()
            vt_result = self.vt_api.lookup_hash(hash_value)
            if vt_result:
                result['sources']['virustotal'] = vt_result
                if vt_result['verdict'] != 'error':
                    result['verdict'] = vt_result['verdict']

        # Query MalwareBazaar
        self.rate_limiter.wait()
        mb_result = self.mb_api.lookup_hash(hash_value)
        if mb_result:
            result['sources']['malwarebazaar'] = mb_result
            if mb_result['verdict'] == 'malicious':
                result['verdict'] = 'malicious'

        # Classify risk level
        result['risk_level'] = self._classify_risk(result['verdict'])

        # Cache result
        if self.cache:
            self.cache.set(hash_value, hash_type, result)

        return result

    def _classify_risk(self, verdict: str) -> str:
        """Classify risk level from verdict"""
        if verdict == 'malicious':
            return 'high'
        elif verdict == 'suspicious':
            return 'medium'
        elif verdict == 'clean':
            return 'low'
        else:
            return 'unknown'

    def lookup_batch(self, hashes: List[str]) -> List[Dict]:
        """Lookup multiple hashes"""
        results = []
        total = len(hashes)

        for i, hash_value in enumerate(hashes, 1):
            if self.verbose:
                print(f"[{i}/{total}] Processing {hash_value[:16]}...", file=sys.stderr)

            result = self.lookup(hash_value)
            results.append(result)

        return results


def format_output_json(results: List[Dict], metadata: Dict) -> str:
    """Format results as JSON"""
    summary = {
        'malicious': sum(1 for r in results if r.get('verdict') == 'malicious'),
        'suspicious': sum(1 for r in results if r.get('verdict') == 'suspicious'),
        'clean': sum(1 for r in results if r.get('verdict') == 'clean'),
        'unknown': sum(1 for r in results if r.get('verdict') == 'unknown'),
    }

    output = {
        'metadata': metadata,
        'summary': summary,
        'results': results
    }

    return json.dumps(output, indent=2)


def format_output_csv(results: List[Dict]) -> str:
    """Format results as CSV"""
    lines = ['Hash,Type,Verdict,Risk_Level,Detection_Ratio,Malware_Family,VT_Link,Cached']

    for r in results:
        hash_val = r.get('hash', '')
        hash_type = r.get('hash_type', '')
        verdict = r.get('verdict', 'unknown')
        risk = r.get('risk_level', 'unknown')
        cached = r.get('cached', False)

        vt_data = r.get('sources', {}).get('virustotal', {})
        detection_ratio = vt_data.get('detection_ratio', 'N/A')
        malware_names = vt_data.get('malware_names', [])
        malware_family = malware_names[0] if malware_names else ''
        vt_link = vt_data.get('permalink', '')

        lines.append(f'{hash_val},{hash_type},{verdict},{risk},{detection_ratio},{malware_family},{vt_link},{cached}')

    return '\n'.join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Hash Lookup - Query file hashes against threat intelligence sources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Lookup single hash
  python lookup.py 5d41402abc4b2a76b9719d911017c592

  # Lookup from file
  python lookup.py --file hashes.txt

  # Export to CSV
  python lookup.py --file hashes.txt --format csv --output results.csv

  # Show only malicious hashes
  python lookup.py --file hashes.txt --filter malicious
        '''
    )

    parser.add_argument(
        'hashes',
        nargs='*',
        help='Hash value(s) to lookup'
    )

    parser.add_argument(
        '--file', '-f',
        help='File with hashes (one per line)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file (default: stdout)'
    )

    parser.add_argument(
        '--format',
        choices=['json', 'csv'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--filter',
        choices=['all', 'malicious', 'suspicious', 'clean', 'unknown'],
        default='all',
        help='Filter results by verdict'
    )

    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable cache'
    )

    parser.add_argument(
        '--cache-ttl',
        type=int,
        default=86400,
        help='Cache TTL in seconds (default: 86400 = 24h)'
    )

    parser.add_argument(
        '--rate-limit', '-r',
        type=int,
        default=4,
        help='Requests per minute (default: 4 for VT free tier)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Collect hashes
    hashes = []

    if args.hashes:
        hashes.extend(args.hashes)

    if args.file:
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    hashes.append(line)

    if not hashes:
        print("Error: No hashes provided. Use arguments or --file", file=sys.stderr)
        sys.exit(1)

    # Check for API key
    if not os.getenv('VT_API_KEY'):
        print("Warning: VT_API_KEY not found. VirusTotal lookups will be skipped.", file=sys.stderr)
        print("Set VT_API_KEY in .env file for VirusTotal integration.", file=sys.stderr)

    # Initialize lookup
    lookup = HashLookup(
        cache_enabled=not args.no_cache,
        cache_ttl=args.cache_ttl,
        rate_limit=args.rate_limit,
        verbose=args.verbose
    )

    # Perform lookups
    if args.verbose:
        print(f"Looking up {len(hashes)} hash(es)...", file=sys.stderr)

    results = lookup.lookup_batch(hashes)

    # Filter results
    if args.filter != 'all':
        results = [r for r in results if r.get('verdict') == args.filter]

    # Show cache stats
    if lookup.cache and args.verbose:
        stats = lookup.cache.stats()
        print(f"\nCache stats: {stats['hits']} hits, {stats['misses']} misses ({stats['hit_rate_percent']}% hit rate)", file=sys.stderr)

    # Format output
    metadata = {
        'lookup_date': datetime.now().isoformat(),
        'total_hashes': len(results),
        'cache_stats': lookup.cache.stats() if lookup.cache else None
    }

    if args.format == 'json':
        output = format_output_json(results, metadata)
    elif args.format == 'csv':
        output = format_output_csv(results)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        if args.verbose:
            print(f"\nOutput written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
