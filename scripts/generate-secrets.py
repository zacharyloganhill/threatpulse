"""
Generate all required secrets for a production ThreatPulse deployment.

Usage:
    python scripts/generate-secrets.py

Prints a ready-to-paste .env block with strong random values for every
secret the application requires. Paste it into your .env file (or your
secrets manager) and keep it out of version control.
"""

import secrets
import sys

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("cryptography package not installed. Run: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def main():
    secret_key        = secrets.token_hex(32)
    admin_password    = secrets.token_urlsafe(24)
    encryption_key    = Fernet.generate_key().decode()

    print("# ── Generated secrets — paste into your .env ───────────────────────────────")
    print(f"SECRET_KEY={secret_key}")
    print(f"ADMIN_PASSWORD={admin_password}")
    print(f"PHANTOMFEED_ENCRYPTION_KEY={encryption_key}")
    print()
    print("# ── Required for production ─────────────────────────────────────────────────")
    print("# Set HOST=0.0.0.0 so the container listens on all interfaces.")
    print("# Set CORS_ORIGINS to your actual domain(s), e.g.:")
    print("# CORS_ORIGINS=https://app.example.com")
    print("HOST=0.0.0.0")
    print("PORT=8000")
    print("DB_PATH=/data/threatpulse.db")
    print()
    print("# Keep the .env file out of version control:")
    print("# echo '.env' >> .gitignore")


if __name__ == "__main__":
    main()
