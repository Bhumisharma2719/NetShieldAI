from __future__ import annotations

import os
import smtplib
import ssl
from email.mime.text import MIMEText

from app.core.config import settings


def send_onboarding_email(to_email: str, password: str, name: str | None = None, user_id: str | None = None) -> None:
    smtp_password = (os.getenv("SMTP_PASSWORD") or settings.smtp_password or "").replace(" ", "")
    smtp_server = os.getenv("SMTP_SERVER") or settings.smtp_server
    smtp_username = os.getenv("SMTP_USERNAME") or settings.smtp_username
    smtp_from_email = os.getenv("SMTP_FROM_EMAIL") or settings.smtp_from_email or smtp_username

    if not smtp_server or not smtp_username or not smtp_password:
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
    message["From"] = smtp_from_email
    message["To"] = to_email

    try:
        if settings.smtp_use_tls:
            with smtplib.SMTP(smtp_server, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_from_email, [to_email], message.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_server, settings.smtp_port, timeout=15) as server:
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_from_email, [to_email], message.as_string())

        print(f"[EMAIL SUCCESS] Mail sent to {to_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send mail: {e}")
