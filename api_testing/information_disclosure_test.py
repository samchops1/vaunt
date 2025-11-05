#!/usr/bin/env python3
"""
Comprehensive Information Disclosure Vulnerability Testing
Tests for exposed files, configs, backups, debug endpoints, and sensitive data
Target: Vaunt API (https://vauntapi.flyvaunt.com)
"""

import requests
import json
import re
import os
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import urljoin
import time

class InformationDisclosureScanner:
    def __init__(self, base_url: str, output_dir: str):
        self.base_url = base_url.rstrip('/')
        self.output_dir = output_dir
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': base_url,
            'exposed_files': [],
            'blocked_but_exists': [],
            'debug_endpoints': [],
            'secrets_found': [],
            'server_info': {},
            'total_tested': 0,
            'vulnerabilities': []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Testing)'
        })

    def test_path(self, path: str, category: str, description: str = "") -> Dict:
        """Test a single path and return results"""
        url = urljoin(self.base_url, path)
        self.results['total_tested'] += 1

        try:
            response = self.session.get(url, timeout=10, allow_redirects=False)

            result = {
                'url': url,
                'path': path,
                'status_code': response.status_code,
                'category': category,
                'description': description,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'exposed': False,
                'content_preview': ''
            }

            # Check if file is exposed (200 OK)
            if response.status_code == 200:
                result['exposed'] = True
                result['content_preview'] = response.text[:500] if len(response.text) > 500 else response.text

                # Save full content
                filename = path.replace('/', '_').replace('.', '_') + '.txt'
                filepath = os.path.join(self.output_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                result['saved_file'] = filepath

                print(f"[+] EXPOSED: {path} (Status: {response.status_code}, Size: {len(response.content)} bytes)")
                self.results['exposed_files'].append(result)

            # 403 means it exists but is blocked
            elif response.status_code == 403:
                print(f"[!] BLOCKED (exists): {path} (Status: 403)")
                self.results['blocked_but_exists'].append(result)

            # Other interesting status codes
            elif response.status_code in [301, 302, 307, 308]:
                print(f"[~] REDIRECT: {path} -> {response.headers.get('Location', 'Unknown')}")

            else:
                print(f"[-] Not found: {path} (Status: {response.status_code})")

            # Small delay to avoid overwhelming the server
            time.sleep(0.1)

            return result

        except requests.exceptions.RequestException as e:
            print(f"[!] ERROR testing {path}: {str(e)}")
            return {
                'url': url,
                'path': path,
                'error': str(e),
                'category': category
            }

    def scan_git_repository(self):
        """Test for exposed .git directory"""
        print("\n" + "="*80)
        print("1. TESTING GIT REPOSITORY EXPOSURE (CRITICAL)")
        print("="*80)

        git_paths = [
            '.git/config',
            '.git/HEAD',
            '.git/logs/HEAD',
            '.git/index',
            '.git/objects/',
            '.git/refs/heads/master',
            '.git/refs/heads/main',
            '.git/description',
            '.git/packed-refs',
        ]

        for path in git_paths:
            self.test_path(path, 'git_exposure', 'Git repository file - CRITICAL if exposed')

    def scan_environment_files(self):
        """Test for exposed environment and config files"""
        print("\n" + "="*80)
        print("2. TESTING ENVIRONMENT FILES EXPOSURE")
        print("="*80)

        env_paths = [
            '.env',
            '.env.local',
            '.env.production',
            '.env.development',
            '.env.staging',
            '.env.backup',
            '.env.old',
            '.env~',
            'config.json',
            'config.yaml',
            'config.yml',
            'secrets.json',
            'secrets.yaml',
            'application.properties',
            'application.yml',
            'application.yaml',
            'settings.json',
            'settings.py',
            'config.php',
            'database.yml',
            'credentials.json',
        ]

        for path in env_paths:
            self.test_path(path, 'environment_files', 'Environment/config file - May contain API keys, DB credentials')

    def scan_backup_files(self):
        """Test for backup files"""
        print("\n" + "="*80)
        print("3. TESTING BACKUP FILES")
        print("="*80)

        backup_paths = [
            'api.js~',
            'api.js.bak',
            'api.js.old',
            'api.js.backup',
            'api.js.swp',
            'index.js~',
            'index.js.bak',
            'server.js~',
            'server.js.bak',
            'app.js~',
            'app.js.bak',
            'backup.sql',
            'db_backup.sql',
            'database.sql',
            'users.sql',
            'dump.sql',
            'backup.zip',
            'backup.tar.gz',
            'site-backup.zip',
            'www.zip',
            'web.zip',
            'database.zip',
        ]

        for path in backup_paths:
            self.test_path(path, 'backup_files', 'Backup file - May contain source code or data')

    def scan_source_maps(self):
        """Test for JavaScript source maps"""
        print("\n" + "="*80)
        print("4. TESTING SOURCE MAPS")
        print("="*80)

        sourcemap_paths = [
            'static/js/main.js.map',
            'static/js/bundle.js.map',
            'assets/index.js.map',
            'assets/main.js.map',
            'js/app.js.map',
            'js/main.js.map',
            'bundle.js.map',
            'app.js.map',
            'index.js.map',
            'main.js.map',
        ]

        for path in sourcemap_paths:
            self.test_path(path, 'source_maps', 'Source map - Reveals original source code')

    def scan_debug_endpoints(self):
        """Test for debug and admin endpoints"""
        print("\n" + "="*80)
        print("5. TESTING DEBUG/ADMIN ENDPOINTS")
        print("="*80)

        debug_paths = [
            'v1/debug',
            'v2/debug',
            'v3/debug',
            'v1/admin',
            'v2/admin',
            'v1/admin/dashboard',
            'v1/test',
            'v2/test',
            'v1/dev',
            'v1/healthcheck',
            'v2/healthcheck',
            'v1/health',
            'v1/status',
            'v2/status',
            'v1/info',
            'v1/version',
            'v2/version',
            'v1/config',
            'v1/env',
            'v1/environment',
            'v1/metrics',
            'v2/metrics',
            'v1/logs',
            'v1/dump',
            'v1/trace',
            'v1/profile',
            'debug',
            'admin',
            'test',
            'dev',
            'healthcheck',
            'health',
            'status',
            'ping',
            'info',
            'version',
            'metrics',
        ]

        for path in debug_paths:
            result = self.test_path(path, 'debug_endpoints', 'Debug/admin endpoint - May reveal sensitive info')
            if result.get('exposed'):
                self.results['debug_endpoints'].append(result)

    def scan_api_documentation(self):
        """Test for exposed API documentation"""
        print("\n" + "="*80)
        print("6. TESTING API DOCUMENTATION ENDPOINTS")
        print("="*80)

        doc_paths = [
            'v1/swagger',
            'v2/swagger',
            'v1/swagger.json',
            'v2/swagger.json',
            'v1/swagger-ui',
            'v1/swagger-ui.html',
            'v1/api-docs',
            'v2/api-docs',
            'v1/docs',
            'v2/docs',
            'v1/documentation',
            'v2/documentation',
            'v1/openapi.json',
            'v2/openapi.json',
            'v1/redoc',
            'swagger',
            'swagger.json',
            'swagger-ui',
            'swagger-ui.html',
            'api-docs',
            'docs',
            'documentation',
            'openapi.json',
            'redoc',
            'graphql',
            'graphiql',
        ]

        for path in doc_paths:
            self.test_path(path, 'api_documentation', 'API documentation - May reveal endpoints and schemas')

    def scan_configuration_files(self):
        """Test for exposed configuration files"""
        print("\n" + "="*80)
        print("7. TESTING CONFIGURATION FILES")
        print("="*80)

        config_paths = [
            'package.json',
            'package-lock.json',
            'composer.json',
            'composer.lock',
            'requirements.txt',
            'Pipfile',
            'Pipfile.lock',
            'Gemfile',
            'Gemfile.lock',
            'yarn.lock',
            'pom.xml',
            'build.gradle',
            'web.config',
            'phpinfo.php',
            'info.php',
            '.htaccess',
            'nginx.conf',
            'apache.conf',
            'Dockerfile',
            'docker-compose.yml',
            '.dockerignore',
            'Makefile',
        ]

        for path in config_paths:
            self.test_path(path, 'configuration_files', 'Configuration file - May reveal dependencies and structure')

    def scan_log_files(self):
        """Test for exposed log files"""
        print("\n" + "="*80)
        print("8. TESTING LOG FILES")
        print("="*80)

        log_paths = [
            'logs/access.log',
            'logs/error.log',
            'logs/app.log',
            'logs/application.log',
            'logs/debug.log',
            'error.log',
            'error_log',
            'access.log',
            'access_log',
            'app.log',
            'application.log',
            'debug.log',
            'npm-debug.log',
            'yarn-error.log',
            'var/log/nginx/access.log',
            'var/log/nginx/error.log',
        ]

        for path in log_paths:
            self.test_path(path, 'log_files', 'Log file - May contain sensitive information')

    def scan_database_admin(self):
        """Test for database admin tools"""
        print("\n" + "="*80)
        print("9. TESTING DATABASE ADMIN TOOLS")
        print("="*80)

        db_admin_paths = [
            'phpmyadmin',
            'phpMyAdmin',
            'pma',
            'PMA',
            'adminer',
            'adminer.php',
            'dbadmin',
            'mysql',
            'myadmin',
            'db',
        ]

        for path in db_admin_paths:
            self.test_path(path, 'database_admin', 'Database admin tool - Direct DB access if accessible')

    def scan_hidden_directories(self):
        """Test for hidden version control and system files"""
        print("\n" + "="*80)
        print("10. TESTING HIDDEN DIRECTORIES/FILES")
        print("="*80)

        hidden_paths = [
            '.svn/entries',
            '.svn/wc.db',
            '.hg/requires',
            '.bzr/branch/last-revision',
            'CVS/Entries',
            '.DS_Store',
            'thumbs.db',
            'Thumbs.db',
            'desktop.ini',
            '.npmrc',
            '.yarnrc',
            '.gitignore',
            '.gitattributes',
            '.editorconfig',
            '.eslintrc',
            '.prettierrc',
        ]

        for path in hidden_paths:
            self.test_path(path, 'hidden_files', 'Hidden system/VCS file')

    def scan_misc_endpoints(self):
        """Test miscellaneous endpoints"""
        print("\n" + "="*80)
        print("11. TESTING MISCELLANEOUS ENDPOINTS")
        print("="*80)

        misc_paths = [
            'robots.txt',
            'sitemap.xml',
            'sitemap_index.xml',
            'security.txt',
            '.well-known/security.txt',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
            'humans.txt',
        ]

        for path in misc_paths:
            self.test_path(path, 'miscellaneous', 'Miscellaneous file - May reveal paths or information')

    def scan_directory_listing(self):
        """Test for directory listing"""
        print("\n" + "="*80)
        print("12. TESTING DIRECTORY LISTING")
        print("="*80)

        dir_paths = [
            'api/',
            'v1/',
            'v2/',
            'v3/',
            'uploads/',
            'static/',
            'assets/',
            'files/',
            'images/',
            'img/',
            'js/',
            'css/',
            'media/',
            'public/',
            'tmp/',
            'temp/',
            'backup/',
            'backups/',
        ]

        for path in dir_paths:
            self.test_path(path, 'directory_listing', 'Directory - Check for listing enabled')

    def check_error_pages(self):
        """Test error pages for information leakage"""
        print("\n" + "="*80)
        print("13. TESTING ERROR PAGES")
        print("="*80)

        error_paths = [
            'v1/nonexistent_endpoint_12345',
            'v2/nonexistent_endpoint_12345',
            'v1/flight/INVALID_ID_12345',
            'v1/user?id=<script>alert(1)</script>',
            'v1/bookings/999999999',
        ]

        for path in error_paths:
            result = self.test_path(path, 'error_pages', 'Intentional error - Check for stack traces')
            if result.get('content_preview'):
                # Check for common leakage patterns
                content = result.get('content_preview', '').lower()
                leakage_patterns = [
                    'stack trace',
                    'at file:',
                    '/var/www',
                    '/home/',
                    'node_modules',
                    'traceback',
                    'exception',
                ]
                for pattern in leakage_patterns:
                    if pattern in content:
                        print(f"    [!] Potential information leakage detected: {pattern}")
                        self.results['vulnerabilities'].append({
                            'type': 'error_information_leakage',
                            'path': path,
                            'pattern_found': pattern
                        })

    def check_server_headers(self):
        """Check response headers for information leakage"""
        print("\n" + "="*80)
        print("14. ANALYZING SERVER HEADERS")
        print("="*80)

        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = dict(response.headers)

            self.results['server_info']['headers'] = headers

            # Check for information-disclosing headers
            disclosure_headers = {
                'Server': 'Server software and version',
                'X-Powered-By': 'Technology stack',
                'X-AspNet-Version': 'ASP.NET version',
                'X-AspNetMvc-Version': 'ASP.NET MVC version',
                'X-Runtime': 'Request processing time',
                'X-Version': 'Application version',
            }

            for header, description in disclosure_headers.items():
                if header in headers:
                    value = headers[header]
                    print(f"[!] {header}: {value} ({description})")
                    self.results['server_info'][header.lower()] = value
                    self.results['vulnerabilities'].append({
                        'type': 'header_disclosure',
                        'header': header,
                        'value': value,
                        'description': description
                    })

        except Exception as e:
            print(f"[!] Error checking headers: {e}")

    def extract_secrets(self):
        """Extract potential secrets from exposed files"""
        print("\n" + "="*80)
        print("15. EXTRACTING SECRETS FROM EXPOSED FILES")
        print("="*80)

        # Patterns for common secrets
        secret_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24,}',
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24,}',
            'JWT Secret': r'jwt[_-]?secret[\'"]?\s*[:=]\s*[\'"]?([^\s\'"]{20,})[\'"]?',
            'Database Password': r'(?:password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]?([^\s\'"]{8,})[\'"]?',
            'API Key': r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            'Generic Secret': r'secret[\'"]?\s*[:=]\s*[\'"]?([^\s\'"]{20,})[\'"]?',
            'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        }

        for exposed in self.results['exposed_files']:
            if 'saved_file' in exposed:
                try:
                    with open(exposed['saved_file'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for secret_type, pattern in secret_patterns.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            secret_value = match.group(1) if match.groups() else match.group(0)
                            print(f"[!!!] {secret_type} found in {exposed['path']}: {secret_value[:20]}...")
                            self.results['secrets_found'].append({
                                'type': secret_type,
                                'file': exposed['path'],
                                'value': secret_value,
                                'context': content[max(0, match.start()-50):min(len(content), match.end()+50)]
                            })

                except Exception as e:
                    print(f"[!] Error extracting secrets from {exposed['saved_file']}: {e}")

    def test_cloud_metadata(self):
        """Test cloud metadata endpoints (AWS/GCP)"""
        print("\n" + "="*80)
        print("16. TESTING CLOUD METADATA ENDPOINTS")
        print("="*80)
        print("[i] Note: These are internal endpoints, unlikely to be accessible from external API")

        # Try SSRF-like requests (will likely fail, but worth documenting)
        metadata_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
        ]

        print("[i] Cloud metadata endpoints would need SSRF vulnerability to access")
        print("[i] Skipping direct tests (not applicable to external API testing)")

    def run_all_scans(self):
        """Execute all scanning modules"""
        print("\n" + "="*80)
        print(f"INFORMATION DISCLOSURE VULNERABILITY SCAN")
        print(f"Target: {self.base_url}")
        print(f"Started: {self.results['timestamp']}")
        print("="*80)

        self.check_server_headers()
        self.scan_git_repository()
        self.scan_environment_files()
        self.scan_backup_files()
        self.scan_source_maps()
        self.scan_debug_endpoints()
        self.scan_api_documentation()
        self.scan_configuration_files()
        self.scan_log_files()
        self.scan_database_admin()
        self.scan_hidden_directories()
        self.scan_misc_endpoints()
        self.scan_directory_listing()
        self.check_error_pages()
        self.extract_secrets()
        self.test_cloud_metadata()

        print("\n" + "="*80)
        print("SCAN COMPLETE")
        print("="*80)
        print(f"Total paths tested: {self.results['total_tested']}")
        print(f"Files exposed: {len(self.results['exposed_files'])}")
        print(f"Files blocked (but exist): {len(self.results['blocked_but_exists'])}")
        print(f"Debug endpoints found: {len(self.results['debug_endpoints'])}")
        print(f"Secrets found: {len(self.results['secrets_found'])}")
        print(f"Vulnerabilities identified: {len(self.results['vulnerabilities'])}")

        return self.results

    def save_results(self, output_file: str):
        """Save results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")


def main():
    # Configuration
    BASE_URL = "https://vauntapi.flyvaunt.com"
    OUTPUT_DIR = "/home/user/vaunt/disclosed_files"
    RESULTS_FILE = "/home/user/vaunt/api_testing/disclosure_scan_results.json"

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Run the scan
    scanner = InformationDisclosureScanner(BASE_URL, OUTPUT_DIR)
    results = scanner.run_all_scans()
    scanner.save_results(RESULTS_FILE)

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"\nCritical findings:")
    print(f"  - Exposed .git repository: {'YES - CRITICAL!' if any('.git' in f['path'] for f in results['exposed_files']) else 'NO'}")
    print(f"  - Exposed .env files: {'YES - CRITICAL!' if any('.env' in f['path'] for f in results['exposed_files']) else 'NO'}")
    print(f"  - Secrets extracted: {len(results['secrets_found'])}")
    print(f"  - Debug endpoints accessible: {'YES' if results['debug_endpoints'] else 'NO'}")
    print(f"\nDetailed results saved to:")
    print(f"  - JSON: {RESULTS_FILE}")
    print(f"  - Exposed files: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
