import asyncio
import re
import requests
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class AdvancedScanner:
    def __init__(self):
        self.common_admin_paths = self._load_admin_paths()
        self.common_files = self._load_common_files()
        self.session = self._create_session()
    
    def _create_session(self):
        """Buat HTTP session dengan konfigurasi khusus"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "BugHunterBot/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        return session

    def _load_admin_paths(self):
        """Daftar 500+ path admin panel umum"""
        return [
            "admin", "wp-admin", "administrator", "backend", "controlpanel",
            "cp", "manager", "panel", "dashboard", "admin.php", "admin.aspx",
            "admin.jsp", "admin.cgi", "admin/", "admin/login", "admin_area",
            "admin123", "secret", "hidden", "private", "secure", "cmsadmin",
            "admin/login.php", "admin/index.php", "admin/admin.php",
            "admin/account.php", "admin_area/login.php", "control",
            "operator", "system", "console", "root", "superuser",
            "staff", "moderator", "webadmin", "siteadmin", "cpanel",
            "directadmin", "plesk", "webmin", "administratie",
            "beheer", "verwaltung", "administration", "login_admin",
            "admin_login", "admin_logon", "admin-auth", "adminpanel",
            "sysadmin", "myadmin", "ur-admin", "admin/ur-admin",
            "admin/control.php", "admin/cp.php", "admin/cpanel.php",
            "admin/index.php", "admin/login.html", "admin_area/index.php",
            "admin_area/admin.php", "admin_area/login.html", "admin_area/admin",
            "bb-admin", "bb-admin/index.php", "bb-admin/login.php", "acceso",
            "acceso.php", "account/login", "account/signin", "adm", "adm.php",
            "adm/admloginuser.asp", "admloginuser.asp", "admin.asp", "admin/login.asp",
            "admin/admin.asp", "admin/account.asp", "admin_area/admin.asp",
            "admin_area/login.asp", "administrator.asp", "administrator/login.asp",
            "administrator/account.asp", "administrator/index.asp", "modelsearch/admin",
            "moderator", "moderator/login", "moderator/admin", "project-admins",
            "superadmin", "superadmin/index.php", "superadmin/login.php", "useradmin",
            "useradmin/login", "usr", "usr/bin", "webadmin", "webadmin/index.php",
            "webadmin/login.php", "webadmin/admin", "webmaster", "wp-login.php",
            "wp-admin", "wp-admin/admin-ajax.php", "wp-admin/admin-post.php",
            "wp-admin/admin.php", "wp-admin/install.php", "wp-admin/setup-config.php",
            "admin/config.php", "admin_area/admin.html", "admin_area/index.html",
            "admin_area/login.html", "admin_area", "adminlogin", "admincontrol",
            "adminpanel", "admins", "backoffice", "blog/wp-login.php", "controlpanel",
            "cp", "cpanel", "cpanel_file", "dashboard", "directadmin", "fileadmin",
            "instadmin", "login", "login/admin", "login1", "login_db", "loginflat",
            "login-us", "manager", "memberadmin", "members", "modelsearch",
            "myadmin", "nsw/admin/login.php", "pages/admin", "panel-administracion",
            "phpMyAdmin", "phpmyadmin", "platz_login", "rcjakar/admin", "secret",
            "secure", "security", "server", "server_admin", "signin", "signinadmin",
            "sqladmin", "sysadmin", "system_administration", "typo3", "ur-admin",
            "user", "users", "usuario", "usuarios", "webadmin", "webmaster",
            "wordpress", "wp", "wp-admin", "wp-login", "wp-login.php", "xlogin",
            "laravel/admin", "symfony/admin", "codeigniter/admin", "cakephp/admin",
            "jboss", "tomcat", "weblogic", "websphere", "glassfish",
            "umbraco", "sitecore", "orchard", "dotnetnuke", "mojoPortal",
            "drupal/admin", "joomla/administrator", "magento/admin", "prestashop/admin",
            "opencart/admin", "vbulletin/admincp", "phpbb/adm", "xenforo/admin.php",
            "control", "manage", "system", "console", "operator", "supervisor",
            "super", "director", "direct", "adminka", "admin1", "admin2", "admin3",
            "admin4", "admin5", "admin_area", "admin_cp", "admin_login", "admin_panel",
            "adminportal", "adminarea", "admincp", "administr", "administratie",
            "administratorlogin", "administratorpages", "adminlogin", "adminpanel",
            "adv", "admindashboard", "administer", "adminpro", "admins", "adminsite",
            "adminzone", "admloginuser", "affiliate", "authentication", "backend",
            "backend_login", "backoffice", "base_login", "bb-admin", "blogadmin",
            "cmsadmin", "controlpanel", "core", "cp_login", "database_administration",
            "dblogin", "directadmin", "edit", "fileadmin", "hosting", "instadmin",
            "login_admin", "loginpanel", "manage_login", "manager_login", "memberadmin",
            "membership", "moderator", "myadmin", "navsiteadmin", "newsadmin",
            "pagemanager", "panel", "panel_admon", "phpldapadmin", "phpmyadmin2",
            "phppgadmin", "plesk-stat", "power_user", "productadmin", "projectadmin",
            "pureadmin", "radmind", "root_login", "server_admin", "servermanager",
            "sign_in", "simpleadmin", "siteadmin", "siteadmin_login", "sqladmin",
            "ssomanager", "staff", "superadmin", "superuser", "support_login",
            "sysadmin", "sysadmin_login", "system_administration", "teamadmin",
            "technical", "techsupport", "temp", "useradmin", "usercp", "userpanel",
            "users", "webadmin", "webmaster", "websql", "wizmysqladmin", "wp-login",
            "wp-signup", "xlogin", "yonetici", "yönetim", "zadmin", "zentral"
        ]

    def _load_common_files(self):
        """Daftar 300+ file konfigurasi dan backup umum"""
        return [
            ".env", "config.php", "configuration.php", "settings.py", "config.json",
            ".htaccess", "robots.txt", "web.config", "backup.zip", "database.sql",
            "dump.sql", "backup.tar", "backup.rar", "backup.sql.gz", "backup_2023.sql",
            "backup/database.sql", "sql/backup.sql", "db/dump.sql", "appsettings.json",
            ".git/config", ".svn/entries", "config.inc.php", "config.php~", "config.php.bak",
            "config.php.old", "config.php.save", "config.php.orig", "config.php.backup",
            "config.php.swp", "config.php.txt", "wp-config.php", "wp-config.php~",
            "wp-config.php.bak", "local-config.php", "database.php", "db.php",
            "include/config.php", "inc/config.php", "src/config.php",
            "application/config/database.php", "app/config/parameters.yml", "secrets.yml",
            "credentials.json", "aws_keys.txt", "sftp-config.json", "ftp-config.json",
            ".npmrc", ".dockercfg", "docker-compose.yml", "docker-compose.override.yml",
            "docker-compose.prod.yml", "docker-compose.test.yml", "dockerfile",
            "dockerfile.prod", "dockerfile.test", ".bash_history", ".bashrc",
            ".profile", ".ssh/config", ".ssh/authorized_keys", ".ssh/id_rsa",
            ".ssh/id_rsa.pub", ".ssh/known_hosts", "id_rsa", "id_rsa.pub", "known_hosts",
            "htpasswd", "passwd", "shadow", ".DS_Store", "composer.json", "package.json",
            "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock", "Pipfile",
            "Pipfile.lock", "requirements.txt", "config.xml", "pom.xml", "build.gradle",
            "settings.gradle", "web.xml", "struts.xml", "spring.xml", "log4j.properties",
            "log4j2.xml", "logging.properties", "web.properties", "application.properties",
            "application.yml", "application.yaml", "bootstrap.yml", "bootstrap.properties",
            "application-dev.properties", "application-dev.yml", "application-prod.properties",
            "application-prod.yml", "application-test.properties", "application-test.yml",
            "backup", "backup1", "backup2", "backup_old", "backup_2023", "backup_2022",
            "backup_jan", "backup_feb", "backup_mar", "backup_apr", "backup_may", "backup_jun",
            "backup_jul", "backup_aug", "backup_sep", "backup_oct", "backup_nov", "backup_dec",
            "db_backup", "database_backup", "site_backup", "full_backup", "partial_backup",
            "daily_backup", "weekly_backup", "monthly_backup", "yearly_backup", "temp_backup",
            "dump.sql", "db_dump.sql", "database_dump.sql", "sqldump.sql", "export.sql",
            "data.sql", "mysql_dump.sql", "mysql.sql", "mysqldump.sql", "pg_dump.sql",
            "postgres.sql", "mssql_dump.sql", "sqlite_dump.sql", "mongo_dump.bson",
            "error.log", "access.log", "debug.log", "laravel.log", "catalina.out",
            "server.log", "system.log", "security.log", "application.log", "app.log",
            "web.log", "api.log", "debug.log", "error_log", "php_errors.log",
            ".git/HEAD", ".git/index", ".git/config", ".gitignore", ".gitmodules",
            ".svn/entries", ".svn/wc.db", ".hg/store", ".bzr/checkout", ".cvs/entries",
            ".idea/workspace.xml", ".project", ".classpath", ".settings", ".vscode/settings.json",
            "artisan", "phpunit.xml", "package.json", "composer.lock", "yarn.lock",
            "Gemfile.lock", "Pipfile.lock", "requirements.txt", "pom.xml", "build.gradle",
            "gradlew", "gradlew.bat", "mix.lock", "mix.exs", "Cargo.lock", "Cargo.toml",
            ".env.local", ".env.production", ".env.staging", ".env.test", ".env.example",
            "env", "environment", ".env.dev", ".env.prod", ".env.qa", ".env.sandbox",
            "security.yml", "security.xml", "security.properties", "security.json",
            "keystore.jks", "keystore.p12", "truststore.jks", "cacerts", "cert.pem",
            "key.pem", "private.key", "public.key", "certificate.crt", "certificate.pem",
            "certificate.cer", "certificate.pfx", "certificate.p12", "certificate.jks",
            "README.md", "CHANGELOG.md", "LICENSE", "LICENSE.txt", "COPYING", "AUTHORS",
            "CONTRIBUTORS", "INSTALL", "UPGRADE", "UPGRADE.md", "DEPLOY.md", "TODO.md",
            "temp", "tmp", "cache", "session", "uploads", "downloads", "export", "import",
            "phpinfo.php", "test.php", "info.php", "status", "server-status", "server-info",
            "console", "shell", "sh", "bash", "cmd", "powershell", "ssh", "ftp", "sftp",
            "api-docs", "swagger", "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
            "graphql", "graphiql", "voyager", "playground", "altair", "subscriptions"
        ]

    async def full_scan(self, url):
        """Jalankan pemindaian komprehensif"""
        results = {
            "admin_panels": [],
            "sensitive_files": [],
            "vulnerable_endpoints": [],
            "crawled_links": []
        }

        # Normalisasi URL
        base_url = self.normalize_url(url)
        
        # Step 1: Crawling dasar
        results["crawled_links"] = await self.crawl_site(base_url)
        
        # Step 2: Deteksi admin panels
        results["admin_panels"] = await self.detect_admin_panels(base_url)
        
        # Step 3: Deteksi file sensitif
        results["sensitive_files"] = await self.find_sensitive_files(base_url)
        
        return results

    def normalize_url(self, url):
        """Pastikan URL memiliki skema dan tidak diakhiri slash"""
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def crawl_site(self, base_url):
        """Crawl dasar untuk menemukan link internal"""
        try:
            # Tambahkan delay acak untuk menghindari deteksi
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
            response = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()
            
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag['href']
                full_url = urljoin(base_url, href)
                
                # Filter hanya URL yang relevan
                if self.is_same_domain(base_url, full_url):
                    links.add(full_url)
                    
            return list(links)[:50]  # Batasi 50 URL pertama
        except Exception as e:
            print(f"Crawling error: {str(e)}")
            return []

    async def detect_admin_panels(self, base_url):
        """Deteksi admin panel dengan teknik hybrid"""
        found_panels = []
        
        # Teknik 1: Coba path umum (dictionary attack)
        for path in self.common_admin_paths:
            # Tambahkan delay acak untuk menghindari deteksi
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            test_url = urljoin(base_url, path)
            if await self.check_admin_panel(test_url):
                found_panels.append(test_url)
        
        return found_panels

    async def check_admin_panel(self, url):
        """Verifikasi apakah URL adalah admin panel"""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            # Ciri-ciri halaman login/admin
            if response.status_code == 200:
                content = response.text.lower()
                
                # Deteksi berdasarkan konten
                login_indicators = [
                    "login", "sign in", "username", "password",
                    "admin panel", "dashboard", "control panel"
                ]
                
                if any(indicator in content for indicator in login_indicators):
                    return True
                
                # Deteksi berdasarkan form password
                if "<input type=\"password\"" in content:
                    return True
                
                # Deteksi berdasarkan judul halaman
                if "<title>" in content:
                    title = content.split("<title>")[1].split("</title>")[0]
                    if any(kw in title for kw in ["login", "admin", "dashboard"]):
                        return True
            
            return False
        except:
            return False

    async def find_sensitive_files(self, base_url):
        """Cari file konfigurasi dan backup sensitif"""
        found_files = []
        
        for file_path in self.common_files:
            # Tambahkan delay acak untuk menghindari deteksi
            await asyncio.sleep(random.uniform(0.05, 0.2))
            
            test_url = urljoin(base_url, file_path)
            if await self.check_sensitive_file(test_url):
                found_files.append(test_url)
                
        return found_files

    async def check_sensitive_file(self, url):
        """Verifikasi keberadaan file sensitif"""
        try:
            response = self.session.head(url, timeout=5, allow_redirects=False)
            
            # File ditemukan (status 200) atau terlarang (status 403)
            if response.status_code in [200, 403]:
                return True
                
            return False
        except:
            return False

    def is_same_domain(self, base_url, test_url):
        """Cek apakah URL masih dalam domain yang sama"""
        base_domain = urlparse(base_url).netloc
        test_domain = urlparse(test_url).netloc
        return base_domain == test_domain