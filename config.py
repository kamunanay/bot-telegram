import os

class Config:
    # Dapatkan token bot dari environment variable
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
    
    # Konfigurasi scanner
    REQUEST_TIMEOUT = 10  # seconds
    MAX_LINKS_TO_SCAN = 50  # Batasi jumlah link yang discan
    USER_AGENT = "BugHunterBot/1.0"
    
    @classmethod
    def validate(cls):
        """Validasi konfigurasi yang diperlukan"""
        if not cls.TELEGRAM_TOKEN:
            raise ValueError("TELEGRAM_TOKEN tidak ditemukan. Setel di environment variable atau file .env")