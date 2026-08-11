from __future__ import annotations

import os
import smtplib
import ssl
from pathlib import Path
from email.mime.text import MIMEText

from dotenv import load_dotenv

from app.core.config import settings

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").replace(" ", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME)
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", str(settings.smtp_use_tls)).strip().lower() in {"1", "true", "yes", "on"}


def send_onboarding_email(to_email: str, password: str, name: str | None = None, user_id: str | None = None) -> None:
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD]):
        print("[EMAIL ERROR] Failed to send mail: SMTP settings are incomplete")
        return

    subject = "NetShield AI Analyst Onboarding"
    recipient_name = name or "Analyst"
    recipient_user_id = user_id or "N/A"

    body = (
        f"Hello {recipient_name},\n\n"
        "You have been onboarded as a Security Analyst on NetShield AI.\n\n"
        f"Your credentials are:\n"
        f"User ID: {recipient_user_id}\n"
        f"Email: {to_email}\n"
        f"Password: {password}\n\n"
        "Please sign in and change your password at the earliest opportunity.\n\n"
        "Regards,\nNetShield AI Security Team"
    )

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = SMTP_FROM_EMAIL or SMTP_USERNAME
    message["To"] = to_email

    try:
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM_EMAIL or SMTP_USERNAME, [to_email], message.as_string())
        else:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM_EMAIL or SMTP_USERNAME, [to_email], message.as_string())

        print(f"[EMAIL SUCCESS] Mail sent to {to_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send mail: {e}")
