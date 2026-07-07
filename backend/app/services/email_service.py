import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import get_settings


def send_email(to_email: str, subject: str, body_text: str):
    settings = get_settings()
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, [to_email], msg.as_string())


def send_admin_self_reset_link(admin_email: str, reset_link: str):
    send_email(
        to_email=admin_email,
        subject="STAR SOC — Réinitialisation de votre mot de passe",
        body_text=f"Cliquez sur ce lien pour définir un nouveau mot de passe (valable 30 minutes) :\n{reset_link}\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.",
    )


def notify_admins_reset_request(admin_emails: list[str], requester_username: str, requester_role: str):
    body = (
        f"L'utilisateur '{requester_username}' (rôle : {requester_role}) a demandé "
        f"la réinitialisation de son mot de passe.\n\n"
        f"Connectez-vous à la plateforme SOC, section Gestion des comptes, "
        f"pour lui définir un nouveau mot de passe."
    )
    for email in admin_emails:
        send_email(to_email=email, subject=f"STAR SOC — Demande de réinitialisation ({requester_username})", body_text=body)
        
def notify_admins_account_locked(admin_emails: list[str], locked_username: str, locked_role: str):
    body = (
        f"Le compte '{locked_username}' (rôle : {locked_role}) a été automatiquement bloqué "
        f"après 3 tentatives de connexion infructueuses.\n\n"
        f"Connectez-vous à la plateforme SOC, section Gestion des comptes, pour :\n"
        f"- Réinitialiser son mot de passe si la personne l'a simplement oublié, ou\n"
        f"- Enquêter s'il s'agit d'une tentative d'accès non autorisée."
    )
    for email in admin_emails:
        send_email(
            to_email=email,
            subject=f"STAR SOC — Compte bloqué ({locked_username})",
            body_text=body,
        )