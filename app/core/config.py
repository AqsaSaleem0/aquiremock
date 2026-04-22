import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv('BASE_URL', 'http://localhost:8000')
CURRENCY_CODE = os.getenv('CURRENCY_CODE', 'USD')
CURRENCY_SYMBOL = os.getenv('CURRENCY_SYMBOL', '$')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET')

# Allow testing without WEBHOOK_SECRET
if not WEBHOOK_SECRET and not os.getenv('TESTING'):
    raise EnvironmentError("CRITICAL: WEBHOOK_SECRET must be set as an environment variable.")






