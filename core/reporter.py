from datetime import datetime

class ReportGenerator:
    def generate_text_report(self, scan_results):
        """Buat laporan hasil pemindaian dalam format Markdown"""
        report = f"🔍 *Hasil Pemindaian untuk {scan_results['base_url']}*\n\n"
        
        # Subdomains
        if scan_results["subdomains"]:
            report += "🌐 *Subdomain Ditemukan:*\n"
            for subdomain in scan_results["subdomains"]:
                report += f"- `{subdomain}`\n"
            report += "\n"
        
        # Admin Panels
        if scan_results["admin_panels"]:
            report += "🚨 *Admin Panels Ditemukan:*\n"
            for panel in scan_results["admin_panels"]:
                report += f"- `{panel}`\n"
            report += "\n"
        
        # Sensitive Files
        if scan_results["sensitive_files"]:
            report += "📁 *File Sensitif Ditemukan:*\n"
            for file in scan_results["sensitive_files"]:
                report += f"- `{file}`\n"
            report += "\n"
        
        # XSS Vulnerabilities
        if scan_results["xss_vulnerabilities"]:
            report += "⚠️ *Kerentanan XSS Ditemukan:*\n"
            for vuln in scan_results["xss_vulnerabilities"]:
                report += f"- URL: `{vuln['url']}`\n"
                report += f"  Payload: `{vuln['payload']}`\n"
            report += "\n"
        
        # SQL Injections
        if scan_results["sql_injections"]:
            report += "🐘 *Kerentanan SQL Injection Ditemukan:*\n"
            for vuln in scan_results["sql_injections"]:
                report += f"- URL: `{vuln['url']}`\n"
                report += f"  Payload: `{vuln['payload']}`\n"
            report += "\n"
        
        # Summary
        report += "📊 *Ringkasan:*\n"
        report += f"- Subdomain: {len(scan_results['subdomains']}\n"
        report += f"- Admin Panels: {len(scan_results['admin_panels'])}\n"
        report += f"- File Sensitif: {len(scan_results['sensitive_files'])}\n"
        report += f"- Kerentanan XSS: {len(scan_results['xss_vulnerabilities'])}\n"
        report += f"- Kerentanan SQLi: {len(scan_results['sql_injections'])}\n"
        report += f"- Link Terdeteksi: {len(scan_results['crawled_links'])}\n"
        report += f"\n_Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return report