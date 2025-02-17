# SMTP Proxy Server for Forwarding Emails

This project implements an SMTP proxy server that allows clients to send emails using a single shared email address, but different credentials. This can be particularly useful if you cannot or prefer not to have multiple email addresses for such clients, but you still want them to have separate and distinct credentials for security purposes. For example, when different services running from the same server are sending mail to an external mail server.

The SMTP proxy intercepts email traffic from apps, checks credentials for each one, modifies the "From" header to ensure the email is sent from a common address, and forwards the email to the desired recipients via a specified SMTP server.

Configuration hot-reloading is supported and will happen on changes to the configuration, so be sure to copy the file elsewhere if you think you could save malformed YAML.


## Use Case

This SMTP proxy server is ideal for scenarios where:

- Multiple applications on a server need to send emails.
- You do not want to or cannot configure separate email addresses for each app.
- You want to ensure all outgoing emails are sent from a single, unified email address.
- You want to avoid sharing credentils between applications.
- You are managing a server with limited email configuration capabilities.


## Requirements

- Python 3.7+
- Required Python libraries:
  - `aiosmtpd`
  - `pyyaml`
  - `watchdog`

Install the required dependencies using pip:

```bash
pip install -r requirements.txt
```


An example systemd process is provided.