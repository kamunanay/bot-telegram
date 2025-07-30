from datetime import datetime

class ReportGenerator:
    def generate_text_report(self, scan_results):
        """Buat laporan hasil pemindaian dalam format Markdown"""
        report = f"🔍 *Hasil Pemindaian untuk {scan_results['base_url']}*\n\n"
        
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
        
        # Summary
        report += "📊 *Ringkasan:*\n"
        report += f"- Admin Panels: {len(scan_results['admin_panels'])}\n"
        report += f"- File Sensitif: {len(scan_results['sensitive_files'])}\n"
        report += f"- Link Terdeteksi: {len(scan_results['crawled_links'])}\n"
        report += f"\n_Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return report