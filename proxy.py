import logging
import smtplib
import base64
import socket
import yaml
import signal
from email import message_from_bytes
from email.parser import BytesParser
from email.policy import default
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, Envelope, Session
import gnupg
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests


# ---------------------------
# Load Configuration
# ---------------------------
def load_config(config_file="config.yml"):
    """Load the YAML configuration file."""
    try:
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
            logger.info("✅ Configuration loaded successfully.")
            return config
    except Exception as e:
        logger.error(f"❌ Error loading configuration: {e}")
        raise


# ---------------------------
# Check Port Availability
# ---------------------------
def is_port_available(host: str, port: int) -> bool:
    """Check if the specified port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


# ---------------------------
# Initialize Logging Configuration
# ---------------------------
def setup_logging():
    """Set up logging configuration with a single stream handler."""
    logger = logging.getLogger()  # Get the root logger

    # Set the logging level to DEBUG
    logger.setLevel(logging.DEBUG)

    # Create a stream handler to output logs to stdout
    stream_handler = logging.StreamHandler(sys.stdout)

    # Set the log format
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    stream_handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(stream_handler)

    return logger


# Setup global logger
logger = setup_logging()


# ---------------------------
# Watchdog for Configuration Reload
# ---------------------------
class ConfigReloadHandler(FileSystemEventHandler):
    """Handler to reload the config when the config file changes."""

    def on_modified(self, event):
        """Triggered when the config file is modified."""
        if event.src_path == "config.yml":
            logger.info("🔄 Configuration file changed, reloading...")
            try:
                global config
                config = load_config("config.yml")  # Reload the config
                logger.info("✅ Configuration reloaded.")
            except Exception as e:
                logger.error(f"❌ Error reloading configuration: {e}")


# ---------------------------
# Initialize Configuration
# ---------------------------
config = load_config("config.yml")

# Extract configuration details
PROXY_HOST = config["smtp_proxy"]["host"]
PROXY_PORT = config["smtp_proxy"]["port"]

SMTP_SERVER_HOST = config["smtp_server"]["host"]
SMTP_SERVER_PORT = config["smtp_server"]["port"]
SMTP_USER = config["smtp_server"]["user"]
SMTP_PASSWORD = config["smtp_server"]["password"]
SMTP_FROM_NAME = config["smtp_server"]["from_name"]
SMTP_FROM_EMAIL = config["smtp_server"]["from_email"]


APP_CREDENTIALS = config["apps"]  # Allowed users' credentials
PASSPHRASE = config["gpg"]["passphrase"]

gpg = gnupg.GPG(gnupghome=config["gpg"]["home"])
gpg.encoding = "utf-8"

KEYSERVER_URL = "https://keys.openpgp.org/vks/v1/by-email/"


# ---------------------------
# EmailAuthenticator Class
# ---------------------------
class EmailAuthenticator:
    """
    Custom authenticator that checks credentials for the SMTP server.
    """

    def __init__(self):
        self.APP_CREDENTIALS = APP_CREDENTIALS

    async def __call__(self, server, session, envelope, mechanism, auth_data):
        fail_nothandled = AuthResult(success=False, handled=False)

        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled

        try:
            if mechanism == "PLAIN":
                decoded = base64.b64decode(auth_data).decode()
                parts = decoded.split("\x00")
                if len(parts) == 3:
                    username = parts[1]
                    password = parts[2]
                else:
                    logger.error("❌ Invalid PLAIN auth data format")
                    return fail_nothandled
            elif mechanism == "LOGIN":
                decoded = base64.b64decode(auth_data).decode()
                if "\x00" in decoded:
                    logger.error("❌ Invalid LOGIN auth data format")
                    return fail_nothandled
                username, password = decoded.split("\x00")

            if (
                username in self.APP_CREDENTIALS
                and self.APP_CREDENTIALS[username]["password"] == password
            ):
                logger.info(f"✅ Authentication successful for {username}")
                return AuthResult(success=True)
            else:
                logger.error(
                    f"❌ Authentication failed for {username}: Incorrect password"
                )
                return fail_nothandled

        except Exception as e:
            logger.error(f"⚠️ Authentication error: {e}")
            return fail_nothandled


# ---------------------------
# EmailProxy Class
# ---------------------------
class EmailProxy:
    """
    Handler for incoming emails that logs the data, performs authentication,
    rewrites the 'From' header, and forwards the email via the specified SMTP server.
    """

    async def handle_EHLO(self, server, session: Session, envelope: Envelope, hostname):
        """Handle the EHLO command and advertise AUTH support."""
        session.host_name = hostname
        return (
            "250-think-server\r\n"
            "250-SIZE 33554432\r\n"
            "250-8BITMIME\r\n"
            "250-SMTPUTF8\r\n"
            "250-AUTH LOGIN PLAIN\r\n"  # Advertise AUTH support
            "250 HELP"
        )

    async def handle_DATA(self, server, session: Session, envelope: Envelope):
        """
        Handle the DATA command, log the email, modify the From header,
        and forward the email via the specified SMTP server.
        """
        mailfrom = envelope.mail_from
        rcpttos = envelope.rcpt_tos
        data = envelope.content

        logger.info(f"📩 Received email from {mailfrom} to {rcpttos}")

        # Log the email content
        logger.debug(f"Mail data:\n{data.decode('utf-8', errors='replace')}")

        # Parse the email
        msg = BytesParser(policy=default).parsebytes(data)

        # Modify the "From" header with the configuration details
        msg.replace_header("From", f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>")

        encrypted_recipients = []
        unencrypted_recipients = []

        for recipient in rcpttos:
            if self.fetch_pgp_key(recipient):
                encrypted_recipients.append(recipient)
            else:
                unencrypted_recipients.append(recipient)

        bcc_recipients = []
        if "Bcc" in msg:
            bcc_recipients = msg["Bcc"].split(",")
            del msg["Bcc"]

        if encrypted_recipients:
            encrypted_msg = self.encrypt_mime_email(msg, encrypted_recipients)
            if encrypted_msg:
                self.send_email(encrypted_msg, encrypted_recipients)

        if unencrypted_recipients:
            plaintext_msg = self.add_unencrypted_warning(msg)
            self.send_email(plaintext_msg, unencrypted_recipients)

        # Send separate emails to each BCC recipient for privacy
        for bcc in bcc_recipients:
            if bcc in encrypted_recipients:
                self.send_email(self.encrypt_mime_email(msg, [bcc]), [bcc])
            else:
                self.send_email(self.add_unencrypted_warning(msg), [bcc])

        return "250 OK"

    def fetch_pgp_key(self, email):
        """Checks if a PGP key exists locally or fetches it from the keyserver."""

        # Check if the key exists locally
        keys = gpg.list_keys(keys=email)
        if keys:
            logger.info(f"✅ PGP key for {email} found locally.")
            return True  # Key exists locally

        # Key does not exist locally, so try fetching from the keyserver
        logger.info(f"🔍 Looking up PGP key for {email} on keyserver...")

        # Request the key from the keyserver API
        keyserver_url = f"{KEYSERVER_URL}{email}"
        try:
            response = requests.get(keyserver_url)

            if response.status_code == 200:
                key_data = response.text
                logger.info(
                    f"✅ Successfully retrieved PGP key for {email} from keyserver."
                )

                # Import the key into GPG
                import_result = gpg.import_keys(key_data)

                if import_result.count > 0:
                    logger.info(
                        f"✅ PGP key for {email} successfully imported into GPG."
                    )
                    return True
                else:
                    logger.warning(f"❌ Failed to import PGP key for {email}.")
                    return False
            else:
                logger.warning(
                    f"❌ No PGP key found for {email}. HTTP status code: {response.status_code}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error while contacting keyserver: {e}")
            return False

    def encrypt_mime_email(self, msg, recipients):
        """Encrypts a full email as PGP/MIME with multiple recipients and hides the subject."""
        original_subject = msg["Subject"]
        msg.replace_header("Subject", "...")

        
        # Convert email to MIME
        mime_msg = MIMEMultipart()
        mime_msg["Subject"] = "..."
        mime_msg["From"] = msg["From"]
        mime_msg["To"] = ", ".join(recipients)

        # Add original subject inside encrypted content
        text_part = MIMEText(f"Subject: {original_subject}\n\n{msg.as_string()}")
        mime_msg.attach(text_part)

        # Encrypt with all recipient keys
        encrypted_data = gpg.encrypt(
            mime_msg.as_string(),
            recipients=recipients,
            sign=SMTP_FROM_EMAIL,
            always_trust=True,
            passphrase=PASSPHRASE,
        )

        if not encrypted_data.ok:
            logger.error(f"❌ Encryption failed: {encrypted_data.stderr}")
            return None

        # Create PGP/MIME encrypted email
        encrypted_email = MIMEMultipart(
            "encrypted", protocol="application/pgp-encrypted"
        )
        encrypted_email["Subject"] = "Encrypted Message"
        encrypted_email["From"] = msg["From"]
        encrypted_email["To"] = ", ".join(recipients)

        # PGP version header
        pgp_header = MIMEBase("application", "pgp-encrypted")
        pgp_header.add_header("Content-Description", "PGP/MIME Versions Header")
        pgp_header.set_payload("Version: 1\r\n")
        encrypted_email.attach(pgp_header)

        # Encrypted email payload
        encrypted_part = MIMEBase("application", "octet-stream")
        encrypted_part.set_payload(str(encrypted_data))
        encrypted_part.add_header(
            "Content-Disposition", "inline", filename="encrypted.asc"
        )
        encrypted_email.attach(encrypted_part)

        return encrypted_email

    def add_unencrypted_warning(self, msg):
        """Adds a warning footer to unencrypted emails for both plain-text and HTML bodies."""
        warning_text = (
            "\n\n⚠️ This email was sent without end-to-end encryption.\n"
            "This mail server supports automatic PGP encryption.\n"
            "Consider setting up a PGP key and publishing it to a keyserver (e.g., keys.openpgp.org)."
        )

        # For multipart emails (text/plain + text/html)
        if msg.is_multipart():
            for part in msg.walk():
                # Check if the part is plain text
                if part.get_content_type() == "text/plain":
                    part.set_payload(part.get_payload() + warning_text)
                # Check if the part is HTML text
                elif part.get_content_type() == "text/html":
                    html_warning = (
                        f"<p><strong>⚠️ This email was sent without end-to-end encryption.</strong><br>"
                        f"This mail server supports automatic PGP encryption.<br>"
                        f"Consider setting up a PGP key and publishing it to a keyserver "
                        f"(e.g., keys.openpgp.org).</p>"
                    )
                    part.set_payload(part.get_payload() + html_warning)
                    part.replace_header(
                        "Content-Transfer-Encoding", "quoted-printable"
                    )  # Ensure HTML part is encoded correctly
        else:
            # If it's a non-multipart message (either plain-text or HTML only)
            if msg.get_content_type() == "text/plain":
                msg.set_payload(msg.get_payload() + warning_text)
            elif msg.get_content_type() == "text/html":
                html_warning = (
                    f"<p><strong>⚠️ This email was sent without end-to-end encryption.</strong><br>"
                    f"This mail server supports automatic PGP encryption.<br>"
                    f"Consider setting up a PGP key and publishing it to a keyserver "
                    f"(e.g., keys.openpgp.org).</p>"
                )
                msg.set_payload(msg.get_payload() + html_warning)
                msg.replace_header("Content-Transfer-Encoding", "quoted-printable")

        return msg

    def send_email(self, msg, recipients):
        """Sends an email via SMTP, ensuring BCC recipients remain private."""
        try:
            logger.info(f"📤 Sending email to {recipients} via SMTP...")
            with smtplib.SMTP(SMTP_SERVER_HOST, SMTP_SERVER_PORT) as smtp_server:
                smtp_server.starttls()
                smtp_server.login(SMTP_USER, SMTP_PASSWORD)
                smtp_server.sendmail(SMTP_FROM_EMAIL, recipients, msg.as_bytes())
            logger.info(f"✅ Email successfully sent to {recipients}")
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")


# ---------------------------
# Run the Proxy Server
# ---------------------------
def run_proxy():
    """Run the SMTP proxy server."""
    if not is_port_available(PROXY_HOST, PROXY_PORT):
        logger.error(f"❌ Port {PROXY_PORT} on {PROXY_HOST} is already in use.")
        exit(1)

    try:
        # Create the EmailAuthenticator instance
        authenticator = EmailAuthenticator()

        # Create the SMTP instance and pass it as handler to the Controller
        smtp_handler = EmailProxy()
        controller = Controller(
            smtp_handler,
            hostname=PROXY_HOST,
            port=PROXY_PORT,
            authenticator=authenticator,
            auth_require_tls=False,
        )

        # Start the config file watcher in a separate thread
        config_watcher = Observer()
        config_watcher.schedule(ConfigReloadHandler(), ".", recursive=False)
        config_watcher.start()

        logger.info(f"🚀 SMTP Proxy started on {PROXY_HOST}:{PROXY_PORT}")
        controller.start()
        sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
        logger.warning(f"{sig} caught, shutting down")
        controller.stop()
        config_watcher.stop()
        config_watcher.join()
    except Exception as e:
        logger.error(f"❌ Error running the proxy: {e}")
        exit(1)


if __name__ == "__main__":
    run_proxy()
