import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_html_email(
    subject: str,
    html_body: str,
    smtp_config: dict,
):
    host = smtp_config["Host"]
    port = smtp_config.get("Port", 2525)
    username = smtp_config["Username"]
    password = smtp_config["Password"]
    from_addr = smtp_config["From"]
    to_addrs = smtp_config["To"]

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = ", ".join(to_addrs)

    part = MIMEText(html_body, 'html', 'utf-8')
    msg.attach(part)

    with smtplib.SMTP(host, port) as server:
        # SMTP2GO soporta TLS en 2525
        server.starttls()
        server.login(username, password)
        server.sendmail(from_addr, to_addrs, msg.as_string())

