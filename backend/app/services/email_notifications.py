from __future__ import annotations

import smtplib
import ssl
from email.mime.text import MIMEText

from app.core.config import settings


def send_onboarding_email(to_email: str, name: str, user_id: str, password: str) -> None:
    if not settings.smtp_server or not settings.smtp_username or not settings.smtp_password:
        return

    from_email = settings.smtp_from_email or settings.smtp_username
    subject = "NetShield AI Analyst Onboarding"
    body = (
        f"Hello {name},\n\n"
        "You have been onboarded as a Security Analyst on NetShield AI.\n\n"
        f"Your credentials are:\n"
        f"User ID: {user_id}\n"
        f"Email: {to_email}\n"
        f"Password: {password}\n\n"
        "Please sign in and change your password at the earliest opportunity.\n\n"
        "Regards,\nNetShield AI Security Team"
    )

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = to_email

    if settings.smtp_use_tls:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(settings.smtp_username, settings.smtp_password)
            server.sendmail(from_email, [to_email], message.as_string())
        return

    with smtplib.SMTP_SSL(settings.smtp_server, settings.smtp_port, timeout=15) as server:
        server.login(settings.smtp_username, settings.smtp_password)
        server.sendmail(from_email, [to_email], message.as_string())
