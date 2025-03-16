import logging
import smtplib
import base64
import socket
import yaml
import signal
from email.parser import BytesParser
from email.policy import default
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, Envelope, Session
import gnupg
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import uuid
import jsonschema
from jsonschema import validate
import threading
import queue

class FIFOQueueLock:
    def __init__(self):
        self.queue = queue.Queue()  # FIFO queue to hold request tickets
        self.lock = threading.Lock()  # Lock to synchronize access to the queue
        self.condition = threading.Condition(self.lock)  # Condition variable for notifying

    def acquire(self):
        with self.lock:
            ticket = object()  # Create a unique ticket for this thread
            self.queue.put(ticket)  # Add the ticket to the queue

        # Wait until our ticket reaches the front of the queue
        with self.lock:
            while self.queue.queue[0] is not ticket:
                self.condition.wait()  # Block the thread until it is its turn

    def release(self):
        with self.lock:
            self.queue.get()  # Remove our ticket from the queue
            self.condition.notify_all()  # Notify the next thread in line

    def clear(self):
        """Clear all pending threads in the queue by notifying them."""
        with self.lock:
            # Clear the queue by removing all items
            self.queue.queue.clear()  # This will clear the queue (all pending tickets)
            # Notify all waiting threads that they can continue
            self.condition.notify_all()  # Wake up all waiting threads, effectively releasing them


# Create a lock
CONFIG_LOCK = FIFOQueueLock()
# if we have requests in progress, they will finish before the config is applied, and the next ones will have it

config_schema = {
    "type": "object",
    "properties": {
        "smtp_proxy": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"}
            },
            "required": ["host", "port"]
        },
        "smtp_server": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "from_name": {"type": "string"},
                "from_email": {"type": "string"}
            },
            "required": ["host", "port", "user", "password", "from_name", "from_email"]
        },
        "apps": {
            "type": "object",
            "patternProperties": {
                "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$": {
                    "type": "object",
                    "properties": {
                        "password": {"type": "string"}
                    },
                    "required": ["password"]
                }
            }
        },
        "gpg": {
            "anyOf": [
                {
                    "type": "object",
                    "properties": {
                        "home": {"type": "string"},
                        "passphrase": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "absent_notice": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "text": {"type": "string"},
                                "html": {"type": "string"}
                            },
                            "anyOf": [
                                { "required": ["text"] },
                                { "required": ["html"] },
                                { "required": ["text", "html"] }
                            ]
                        },
                        "email_http_keyserver": {"type": "string"}
                    },
                    "required": ["home", "enabled", "absent_notice", "email_http_keyserver"]
                },
                {
                    "type": "null"  # Allows the key to be absent or null
                }
            ]
        },
        "id_domain": {"type": "string"},
        "email_http_keyserver": {"type": "string"}
    },
    "required": ["smtp_proxy", "smtp_server", "apps", "gpg", "id_domain"]
}


# ---------------------------
# Load Configuration
# ---------------------------
def load_config(config_file="config.yml"):
    """Load the YAML configuration file."""
    try:
        CONFIG_LOCK.acquire()
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)

            validate(instance=config, schema=config_schema)
            logger.info("✅ Configuration loaded successfully.")
            return config
    except yaml.YAMLError as e:
        logger.error(f"❌ YAML Error: {e}")
        raise
    except jsonschema.exceptions.ValidationError as e:
        logger.error(f"❌ Schema Validation Error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"❌ Error loading configuration: {e}")
        raise
    finally:
        CONFIG_LOCK.release()


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


controller = None

# ---------------------------
# Initialize Configuration
# ---------------------------
config = load_config("config.yml")



def get_conf(param: str):
    if param == "PROXY_HOST":
        return config["smtp_proxy"]["host"]
    elif param == "PROXY_PORT":
        return config["smtp_proxy"]["port"]
    elif param == "SMTP_SERVER_HOST":
        return config["smtp_server"]["host"]
    elif param == "SMTP_SERVER_PORT":
        return config["smtp_server"]["port"]
    elif param == "SMTP_USER":
        return config["smtp_server"]["user"]
    elif param == "SMTP_PASSWORD":
        return config["smtp_server"]["password"]
    elif param == "SMTP_FROM_NAME":
        return config["smtp_server"]["from_name"]
    elif param == "SMTP_FROM_EMAIL":
        return config["smtp_server"]["from_email"]
    elif param == "APP_CREDENTIALS":
        return config["apps"]
    elif param == "PASSPHRASE":
        return config["gpg"]["passphrase"] if get_conf("GPG_ENABLED") and "passphrase" in config["gpg"] else None
    elif param == "GPG_ENABLE":
        return config["gpg"]["enable"] if get_conf("GPG_ENABLED") else False
    elif param == "WARN_ABSENT_GPG":
        return config["gpg"]["absent_notice"]["enabled"] if get_conf("GPG_ENABLED") else False
    elif param == "GPG_ABSENT_NOTICE_TEXT":
        return config["gpg"]["absent_notice"]["text"] if get_conf("GPG_ENABLED") else None
    elif param == "GPG_ABSENT_NOTICE_HTML":
        return config["gpg"]["absent_notice"]["html"] if get_conf("GPG_ENABLED") else None
    elif param == "ID_DOMAIN":
        return config["id_domain"]
    elif param == "KEYSERVER_URL":
        return config["gpg"]["email_http_keyserver"] if get_conf("GPG_ENABLED") else None
    elif param == "GPG_ENABLED":
        return "gpg" in config and gpg["enabled"]
    else:
        raise ValueError(f"Unknown parameter: {param}")
    
    
if "gpg in config":        
    gpg = gnupg.GPG(gnupghome=config["gpg"]["home"])
    gpg.encoding = "utf-8"
else: 
    gpg = None


# ---------------------------
# Watchdog for Configuration Reload
# ---------------------------
class ConfigReloadHandler(FileSystemEventHandler):
    """Handler to reload the config when the config file changes."""

    def on_modified(self, event):
        CONFIG_LOCK.acquire()
        try:
            global gpg, config
            """Triggered when the config file is modified."""
            if event.src_path == "config.yml":
                logger.info("🔄 Configuration file changed, reloading...")
                try:
                    new_config = load_config("config.yml")  # Reload the config
                    if new_config["smtp_proxy"]["host"] != config["smtp_proxy"]["host"] \
                        or new_config["smtp_proxy"]["port"] != new_config["smtp_proxy"]["port"]:
                        config = new_config
                        if controller is not None:
                            controller.stop()
                            CONFIG_LOCK.clear()
                            controller.start()
                    else:
                        config = new_config
                    if get_conf("GPG_ENABLED"):        
                        gpg = gnupg.GPG(gnupghome=config["gpg"]["home"])
                        gpg.encoding = "utf-8"
                    else: 
                        gpg = None

                    logger.info("✅ Configuration reloaded.")
                except Exception as e:
                    logger.error(f"❌ Error reloading configuration: {e}")
        finally:
            CONFIG_LOCK.release()


# ---------------------------
# EmailAuthenticator Class
# ---------------------------
class EmailAuthenticator:
    """
    Custom authenticator that checks credentials for the SMTP server.
    """

    def __init__(self):
       pass

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

            app_credentials = get_conf("APP_CREDENTIALS") # avoid race condition in if
            if (
                username in app_credentials
                and app_credentials[username]["password"] == password
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

    async def handle_EHLO(
        self, server, session: Session, envelope: Envelope, hostname
    ) -> str:
        """Handle the EHLO command and advertise AUTH support."""
        session.host_name = hostname
        return (
            "250-smtp-mailproxy\r\n"
            "250-SIZE 33554432\r\n"
            "250-8BITMIME\r\n"
            "250-SMTPUTF8\r\n"
            "250-AUTH LOGIN PLAIN\r\n"  # Advertise AUTH support
            "250 HELP"
        )

    async def handle_DATA(self, server, session: Session, envelope: Envelope) -> str:

        CONFIG_LOCK.acquire()
        try:
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
            msg.replace_header("From", f"{get_conf("SMTP_FROM_NAME")} <{get_conf("SMTP_FROM_EMAIL")}>")

            encrypted_recipients = []
            unencrypted_recipients = []

            for recipient in rcpttos:
                if get_conf("GPG_ENABLED") and  self.fetch_pgp_key(recipient):
                    encrypted_recipients.append(recipient)
                else:
                    unencrypted_recipients.append(recipient)

            bcc_recipients = []
            if "Bcc" in msg:
                bcc_recipients = msg["Bcc"].split(",")
                del msg["Bcc"]

            if "X-Mailer" in msg:
                del msg["X-Mailer"]

            msg.replace_header(
                "Message-ID", "<" + str(uuid.uuid4()) + "@" + get_conf("ID_DOMAIN") + ">"
            )

            if encrypted_recipients:
                encrypted_msg = self.encrypt_mime_email(msg, encrypted_recipients)
                if encrypted_msg:
                    self.send_email(encrypted_msg, encrypted_recipients)

            if unencrypted_recipients:
                plaintext_msg = (
                    self.add_unencrypted_warning(msg) if get_conf("WARN_ABSENT_GPG") else msg
                )
                self.send_email(plaintext_msg, unencrypted_recipients)

            # Send separate emails to each BCC recipient for privacy
            for bcc in bcc_recipients:
                if bcc in encrypted_recipients:
                    self.send_email(self.encrypt_mime_email(msg, [bcc]), [bcc])
                else:
                    self.send_email(
                        self.add_unencrypted_warning(msg) if get_conf("WARN_ABSENT_GPG") else msg, [bcc]
                    )

            return "250 OK"
        finally:
            CONFIG_LOCK.release()


    def fetch_pgp_key(self, email: str) -> bool:
        """Checks if a PGP key exists locally or fetches it from the keyserver."""

        # Check if the key exists locally
        keys = gpg.list_keys(keys=email)
        if keys:
            logger.info(f"✅ PGP key for {email} found locally.")
            return True  # Key exists locally

        # Key does not exist locally, so try fetching from the keyserver
        logger.info(f"🔍 Looking up PGP key for {email} on keyserver...")

        # Request the key from the keyserver API
        key_url = f"{get_conf("KEYSERVER_URL")}{email}"
        try:
            response = requests.get(key_url)

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

    def encrypt_mime_email(self, msg: Message, recipients: list[str]) -> MIMEMultipart:
        """Encrypts a full email as PGP/MIME, including attachments, and sets the subject to '...'."""
        # msg.replace_header("Subject", "...")

        # Create a new MIME message to hold the encrypted content
        encrypted_email = MIMEMultipart(
            "encrypted", protocol="application/pgp-encrypted"
        )
        encrypted_email["Subject"] = msg["Subject"]
        encrypted_email["From"] = msg["From"]
        encrypted_email["To"] = ", ".join(recipients)

        # Add Autocrypt header (optional, for Autocrypt support)
        autocrypt_key = self.get_autocrypt_key(get_conf("SMTP_FROM_EMAIL"))
        if autocrypt_key:
            encrypted_email["Autocrypt"] = autocrypt_key

        # PGP version header
        pgp_header = MIMEBase("application", "pgp-encrypted")
        pgp_header.add_header("Content-Description", "PGP/MIME version identification")
        pgp_header.set_payload("Version: 1\r\n")
        encrypted_email.attach(pgp_header)

        # Encrypt the email body and attachments
        encrypted_part = self.encrypt_message_with_attachments(msg, recipients)
        if not encrypted_part:
            logger.error("❌ Failed to encrypt message with attachments.")
            return None

        # Attach the encrypted payload
        encrypted_email.attach(encrypted_part)

        return encrypted_email

    def get_autocrypt_key(self, email: str) -> str:
        # Fetch the public key for the given email
        keys = gpg.list_keys(keys=email)
        if not keys:
            logger.warning(f"❌ No PGP key found for {email} in the GPG keyring.")
            return None

        # Export the public key in ASCII-armored format
        key_data = gpg.export_keys(email, armor=True)
        if not key_data:
            logger.error(f"❌ Failed to export PGP key for {email}.")
            return None

        # Encode the key data in base64
        keydata_base64 = base64.b64encode(key_data.encode("utf-8")).decode("utf-8")

        # Construct the Autocrypt header
        autocrypt_header = f"addr={email}; keydata={keydata_base64}"

        return autocrypt_header

    def encrypt_message_with_attachments(
        self, msg: Message, recipients: list[str]
    ) -> MIMEBase:
        """Encrypts the entire MIME body as a single unit."""
        # Convert the entire message to a string
        message_str = msg.as_string()

        # Encrypt the entire message
        encrypted_data = gpg.encrypt(
            message_str,
            recipients=recipients,
            sign=get_conf("SMTP_FROM_EMAIL"),
            always_trust=True,
            passphrase=get_conf("PASSPHRASE")
        )

        if not encrypted_data.ok:
            logger.error(f"❌ Encryption failed: {encrypted_data.stderr}")
            return None

        # Create the encrypted payload part
        encrypted_part = MIMEBase("application", "octet-stream")
        encrypted_part.set_payload(str(encrypted_data))
        encrypted_part.add_header("Content-Description", "OpenPGP encrypted message")
        encrypted_part.add_header(
            "Content-Disposition", "inline", filename="encrypted.asc"
        )

        return encrypted_part

    def add_unencrypted_warning(self, msg: Message) -> Message:
        """Adds a warning footer to unencrypted emails for both plain-text and HTML bodies."""

        # For multipart emails (text/plain + text/html)
        if msg.is_multipart():
            for part in msg.walk():
                # Check if the part is plain text
                if part.get_content_type() == "text/plain":
                    part.set_payload(part.get_payload() + get_conf("GPG_ABSENT_NOTICE_TEXT"))
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
                msg.set_payload(msg.get_payload() + get_conf("GPG_ABSENT_NOTICE_TEXT"))
            elif msg.get_content_type() == "text/html":
                msg.set_payload(msg.get_payload() + get_conf("GPG_ABSENT_NOTICE_HTML"))
                msg.replace_header("Content-Transfer-Encoding", "quoted-printable")

        return msg

    def send_email(self, msg: Message, recipients: list[str]) -> None:
        """Sends an email via SMTP, ensuring BCC recipients remain private."""

        try:
            logger.info(f"📤 Sending email to {recipients} via SMTP...")
            with smtplib.SMTP(get_conf("SMTP_SERVER_HOST"), get_conf("SMTP_SERVER_PORT")) as smtp_server:
                smtp_server.starttls()
                smtp_server.login(get_conf("SMTP_USER"), get_conf("SMTP_PASSWORD"))
                smtp_server.sendmail(
                    get_conf("SMTP_FROM_EMAIL"), recipients, msg.as_string().encode("utf-8")
                )
            logger.info(f"✅ Email successfully sent to {recipients}")
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")


# ---------------------------
# Run the Proxy Server
# ---------------------------
def run_proxy():
    global controller
    """Run the SMTP proxy server."""
    if not is_port_available(get_conf("PROXY_HOST"), get_conf("PROXY_PORT")):
        logger.error(f"❌ Port {get_conf("PROXY_PORT")} on {get_conf("PROXY_HOST")} is already in use.")
        exit(1)

    try:
        # Create the EmailAuthenticator instance
        authenticator = EmailAuthenticator()

        # Create the SMTP instance and pass it as handler to the Controller
        smtp_handler = EmailProxy()
        controller = Controller(
            smtp_handler,
            hostname=get_conf("PROXY_HOST"),
            port=get_conf("PROXY_PORT"),
            authenticator=authenticator,
            auth_require_tls=False,
        )

        # Start the config file watcher in a separate thread
        config_watcher = Observer()
        config_watcher.schedule(ConfigReloadHandler(), ".", recursive=False)
        config_watcher.start()

        logger.info(f"🚀 SMTP Proxy started on {get_conf("PROXY_HOST")}:{get_conf("PROXY_PORT")}")
        controller.start()
        sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
        logger.warning(f"{sig} caught, shutting down")
        CONFIG_LOCK.clear()
        controller.stop()
        config_watcher.stop()
        config_watcher.join()
    except Exception as e:
        logger.error(f"❌ Error running the proxy: {e}")
        exit(1)


if __name__ == "__main__":
    run_proxy()
