import logging
import smtplib
import base64
import socket
import yaml
import signal
from email.parser import BytesParser
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import  AuthResult
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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

app_credentials = config["apps"]  # Allowed users' credentials


# ---------------------------
# EmailAuthenticator Class
# ---------------------------
class EmailAuthenticator:
    """
    Custom authenticator that checks credentials for the SMTP server.
    """

    def __init__(self):
        self.app_credentials = app_credentials

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

            if username in self.app_credentials and self.app_credentials[username]["password"] == password:
                logger.info(f"✅ Authentication successful for {username}")
                return AuthResult(success=True)
            else:
                logger.error(f"❌ Authentication failed for {username}: Incorrect password")
                return fail_nothandled

        except Exception as e:
            logger.error(f"⚠️ Authentication error: {e}")
            return fail_nothandled


# ---------------------------
# EmailLoggingProxy Class
# ---------------------------
class EmailLoggingProxy:
    """
    Handler for incoming emails that logs the data, performs authentication,
    rewrites the 'From' header, and forwards the email via the specified SMTP server.
    """

    async def handle_EHLO(self, server, session, envelope, hostname):
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

    async def handle_DATA(self, server, session, envelope):
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

        # Validate sender against allowed app credentials
        if mailfrom not in app_credentials:
            logger.error(f"🚫 Unauthorized sender: {mailfrom}")
            return "550 Unauthorized sender"

        # Parse the email
        msg = BytesParser(policy=default).parsebytes(data)

        # Modify the "From" header with the configuration details
        msg.replace_header("From", f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>")

        # Forward the email via the specified SMTP server
        try:
            logger.info(f"📤 Forwarding email to {rcpttos} via SMTP server...")
            with smtplib.SMTP(SMTP_SERVER_HOST, SMTP_SERVER_PORT) as smtp_server:
                smtp_server.starttls()  # Upgrade connection to TLS
                smtp_server.login(SMTP_USER, SMTP_PASSWORD)
                smtp_server.sendmail(SMTP_FROM_EMAIL, rcpttos, msg.as_bytes())
            logger.info(f"✅ Email successfully forwarded to {rcpttos}")
            return "250 OK"
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")
            return "550 Internal server error"


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
        smtp_handler = EmailLoggingProxy()
        controller = Controller(smtp_handler, hostname=PROXY_HOST, port=PROXY_PORT, authenticator=authenticator, auth_require_tls=False)
        
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
