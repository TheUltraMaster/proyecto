"""Envio simple de correo para veredictos accionables (SMTP de Gmail)."""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage

log = logging.getLogger(__name__)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT = 15
NOTIFY_VERDICTS = ("real", "uncertain")


def send_alert_email(subject: str, body: str) -> None:
    """Envia un correo de texto plano. Nunca propaga errores: es best-effort."""
    sender = os.environ.get("ALERT_EMAIL_FROM", "").strip()
    password = os.environ.get("ALERT_EMAIL_PASSWORD", "").replace(" ", "")
    recipients = [
        address.strip()
        for address in os.environ.get("ALERT_EMAIL_TO", "").split(",")
        if address.strip()
    ]
    if not (sender and password and recipients):
        return

    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
            smtp.starttls()
            smtp.login(sender, password)
            smtp.send_message(message)
        log.info(f"Alerta enviada por correo a {len(recipients)} destinatario(s)")
    except Exception as e:
        log.warning(f"No se pudo enviar el correo de alerta: {type(e).__name__}: {e}")
