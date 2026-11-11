"""Send yourself the PhishLens demo emails (Safe, Suspicious, Malicious) from a second Gmail account.

Usage:
    python tools/send_test_emails.py --sender other.account@gmail.com --to you@gmail.com
    python tools/send_test_emails.py --dry-run          # just list what would be sent

The app password is asked for when the script runs and is never stored. Create one at
https://myaccount.google.com/apppasswords (needs 2-Step Verification) and delete it afterwards.
Every link points to a reserved ".example" domain or a documentation-only IP, so nothing leads anywhere.
"""
import argparse
import getpass
import smtplib
from email.message import EmailMessage

PAYPAL_HTML = """\
<p>Dear customer,</p>
<p>We noticed unusual activity and have <b>limited your account</b>.
Please verify your details within 24 hours or your account will be closed.</p>
<p><a href="https://paypa1-secure.example/login">www.paypal.com</a></p>
<p>If the link doesn't open, use our <a href="http://192.0.2.10/verify">backup page</a>.</p>
<p>PayPal Security Team</p>
"""

MICROSOFT_HTML = """\
<p>Hello,</p>
<p>We detected a sign-in to your Microsoft account from a new device.</p>
<p>If this was you, you can ignore this message. If not, please review your recent activity:</p>
<p><a href="https://rnicrosoft-login.example/activity">Review recent activity</a></p>
<p>Thanks,<br>The Microsoft account team</p>
"""

# What each email contains, and the card PhishLens should show for it.
EMAILS = [
    {"expect": "Safe 0", "name": "", "subject": "Lunch tomorrow?",
     "text": "Hi! Are we still on for lunch tomorrow at 12?"},
    {"expect": "Suspicious 50", "name": "Microsoft Account Team",
     "subject": "New sign-in to your Microsoft account", "html": MICROSOFT_HTML},
    {"expect": "Malicious 85", "name": "PayPal Security", "reply_to": "support@paypal-help.example",
     "subject": "Action required: your account has been limited", "html": PAYPAL_HTML},
    {"expect": "Malicious 100", "name": "PayPal Security", "reply_to": "support@paypal-help.example",
     "subject": "Your invoice is attached", "html": PAYPAL_HTML,
     "attachment": ("invoice.pdf.html", b"<p>Harmless test file.</p>")},
]


def build(spec: dict, sender: str, to: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = f"{spec['name']} <{sender}>" if spec["name"] else sender
    msg["To"] = to
    msg["Subject"] = f"{spec['subject']} (PhishLens demo: expect {spec['expect']})"
    if "reply_to" in spec:
        msg["Reply-To"] = spec["reply_to"]
    msg.set_content(spec.get("text", "This email needs an HTML viewer."))
    if "html" in spec:
        msg.add_alternative(spec["html"], subtype="html")
    if "attachment" in spec:
        filename, data = spec["attachment"]
        msg.add_attachment(data, maintype="text", subtype="html", filename=filename)
    return msg


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sender", help="the second Gmail account that sends the emails")
    parser.add_argument("--to", help="your Gmail address, where PhishLens is installed")
    parser.add_argument("--dry-run", action="store_true", help="list the emails without sending")
    args = parser.parse_args()

    if args.dry_run:
        for spec in EMAILS:
            print(f"{spec['expect']:<14} {spec['subject']}")
        return
    if not (args.sender and args.to):
        parser.error("--sender and --to are required (or use --dry-run)")

    password = getpass.getpass(f"App password for {args.sender}: ")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(args.sender, password)
        for spec in EMAILS:
            smtp.send_message(build(spec, args.sender, args.to))
            print(f"Sent: expect {spec['expect']:<14} {spec['subject']}")


if __name__ == "__main__":
    main()
