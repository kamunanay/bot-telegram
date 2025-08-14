import asyncio
import logging
import os
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from core.scanner import AdvancedScanner
from core.reporter import ReportGenerator
from config import Config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

bot = Bot(token=Config.TELEGRAM_TOKEN)
dp = Dispatcher()

scanner = AdvancedScanner()
reporter = ReportGenerator()

@dp.message(Command("start", "help"))
async def cmd_start(message: types.Message):
    await message.answer(
        text=(
            "🛡️ *BugHunter Bot - Web Security Scanner*\n\n"
            "Kirim URL website untuk memulai pemindaian:\n"
            "Contoh: `https://example.com` atau `http://localhost:8000`\n\n"
            "Fitur deteksi:\n"
            "- Scan Subdomain (150+ pola)\n"
            "- Admin Panels (500+ pola)\n"
            "- Sensitive Files (300+ pola)\n"
            "- Kerentanan XSS (20+ payload)\n"
            "- Kerentanan SQL Injection (20+ payload)\n"
            "- Crawling Link Internal\n\n"
            "Gunakan perintah /risks untuk melihat daftar risiko yang dideteksi"
        ),
        parse_mode="Markdown"
    )

@dp.message(Command("risks"))
async def cmd_risks(message: types.Message):
    await message.answer(
        "🔍 *Daftar Pola Risiko yang Dideteksi:*\n\n"
        "1. Subdomain Aktif (www, api, dev, etc.)\n"
        "2. Admin Panels (admin.php, wp-admin, etc.)\n"
        "3. Login Pages (login.aspx, signin.jsp, etc.)\n"
        "4. Backup Files (.bak, .zip, .sql, etc.)\n"
        "5. Config Files (.env, config.ini, etc.)\n"
        "6. Kerentanan XSS (Reflected & Stored)\n"
        "7. Kerentanan SQL Injection (Error-based)\n"
        "8. Database Interfaces (phpMyAdmin, adminer)\n"
        "9. Developer Files (package.json, composer.lock)\n"
        "10. Version Control (.git/, .svn/)\n\n"
        "Total 1000+ pola deteksi siap digunakan!",
        parse_mode="Markdown"
    )

@dp.message(lambda message: message.text and message.text.startswith(('http://', 'https://')))
async def handle_scan_request(message: types.Message):
    url = message.text.strip()
    user_id = message.from_user.id
    
    # Kirim notifikasi pemrosesan
    processing_msg = await message.answer(f"🔍 Memulai pemindaian mendalam {url}...")
    
    try:
        # Jalankan pemindaian
        scan_results = await scanner.full_scan(url)
        
        # Format hasil
        formatted_results = {
            "base_url": url,
            "subdomains": scan_results["subdomains"],
            "admin_panels": scan_results["admin_panels"],
            "sensitive_files": scan_results["sensitive_files"],
            "xss_vulnerabilities": scan_results["xss_vulnerabilities"],
            "sql_injections": scan_results["sql_injections"],
            "crawled_links": scan_results["crawled_links"]
        }
        
        # Generate report
        report_text = reporter.generate_text_report(formatted_results)
        
        # Kirim hasil
        if (formatted_results["admin_panels"] or 
            formatted_results["sensitive_files"] or
            formatted_results["xss_vulnerabilities"] or
            formatted_results["sql_injections"]):
            await message.answer(
                text="⚠️ *Potensi Kerentanan Ditemukan!*",
                parse_mode="Markdown"
            )
        else:
            await message.answer(
                text="✅ *Pemindaian Selesai - Tidak Ditemukan Kerentanan*",
                parse_mode="Markdown"
            )
        
        await message.answer(report_text, parse_mode="Markdown")
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        await message.answer(f"❌ Error: {str(e)}")
    finally:
        await bot.delete_message(chat_id=processing_msg.chat.id, message_id=processing_msg.message_id)

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())