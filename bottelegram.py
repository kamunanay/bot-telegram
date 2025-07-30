import asyncio
import logging
import os
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import URLInputFile
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

# URL untuk GIF assets
ASSETS = {
    "start": "https://media1.giphy.com/media/v1.Y2lkPTZjMDliOTUyYXVxY3kxbWdmbXZ2aHJ2YWFndG1pc2V5cTJiYXFxZnIwcmNnd2tnciZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MD0svLSDeudszrNrp0/giphy.gif",
    "success": "https://media3.giphy.com/media/v1.Y2lkPTZjMDliOTUyaWdwY2liYmh4bWUwbWp1ZWU0eHFzY2lscGt1anQybWVuN2ExaDBqeiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/8Fr8hmVNAg0GiQ6rI4/giphy.gif",
    "warning": "https://media4.giphy.com/media/v1.Y2lkPTZjMDliOTUybmI1ZDlxNWV6emZuZWNjbmNkNnowZzEyYWttZWd1czRyOGRpZGxxdCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/TZxsVSO0vC1L0N0kid/giphy.gif"
}

@dp.message(Command("start", "help"))
async def cmd_start(message: types.Message):
    await message.answer_animation(
        animation=URLInputFile(ASSETS["start"]),
        caption=(
            "🛡️ *BugHunter Bot - Web Security Scanner*\n\n"
            "Kirim URL website untuk memulai pemindaian:\n"
            "Contoh: `https://example.com` atau `http://localhost:8000`\n\n"
            "Fitur deteksi:\n"
            "- Admin Panels (500+ pola)\n"
            "- Sensitive Files (300+ pola)\n"
            "- SQL Injection/XSS\n"
            "- Struktur direktori\n"
            "- Dan banyak lagi...\n\n"
            "Gunakan perintah /risks untuk melihat daftar risiko yang dideteksi"
        ),
        parse_mode="Markdown"
    )

@dp.message(Command("risks"))
async def cmd_risks(message: types.Message):
    await message.answer(
        "🔍 *Daftar Pola Risiko yang Dideteksi:*\n\n"
        "1. Admin Panels (admin.php, wp-admin, etc.)\n"
        "2. Login Pages (login.aspx, signin.jsp, etc.)\n"
        "3. Backup Files (.bak, .zip, .sql, etc.)\n"
        "4. Config Files (.env, config.ini, etc.)\n"
        "5. Database Interfaces (phpMyAdmin, adminer)\n"
        "6. Developer Files (package.json, composer.lock)\n"
        "7. Version Control (.git/, .svn/)\n"
        "8. Debug Files (debug.log, error.log)\n"
        "9. API Endpoints (api/, graphql)\n"
        "10. Framework Files (laravel.log, artisan)\n\n"
        "Total 800+ pola deteksi siap digunakan!",
        parse_mode="Markdown"
    )

@dp.message(lambda message: message.text and message.text.startswith(('http://', 'https://')))
async def handle_scan_request(message: types.Message):
    url = message.text.strip()
    user_id = message.from_user.id
    
    # Kirim notifikasi pemrosesan
    processing_msg = await message.answer(f"🔍 Memulai pemindaian {url}...")
    
    try:
        # Jalankan pemindaian
        scan_results = await scanner.full_scan(url)
        
        # Format hasil
        formatted_results = {
            "base_url": url,
            "admin_panels": scan_results["admin_panels"],
            "sensitive_files": scan_results["sensitive_files"],
            "vulnerable_endpoints": scan_results["vulnerable_endpoints"],
            "crawled_links": scan_results["crawled_links"]
        }
        
        # Generate report
        report_text = reporter.generate_text_report(formatted_results)
        
        # Kirim hasil
        if formatted_results["admin_panels"] or formatted_results["sensitive_files"]:
            await message.answer_animation(
                animation=URLInputFile(ASSETS["warning"]),
                caption="⚠️ *Potensi Kerentanan Ditemukan!*",
                parse_mode="Markdown"
            )
        else:
            await message.answer_animation(
                animation=URLInputFile(ASSETS["success"]),
                caption="✅ *Pemindaian Selesai*",
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