import os

class Config:
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "7890620930:AAHHmKIxCFKxKWm0KqsA_gYWNYTJokymul8")
    
    
    REQUEST_TIMEOUT = 10  
    MAX_LINKS_TO_SCAN = 50 
    MAX_SUBDOMAINS_TO_SCAN = 150  
    USER_AGENT = "BugHunterBot/2.0"
    
    @classmethod
    def validate(cls):
        """Validasi konfigurasi yang diperlukan"""
        if not cls.TELEGRAM_TOKEN:
            raise ValueError("TELEGRAM_TOKEN tidak ditemukan. Setel di environment variable atau file .env")