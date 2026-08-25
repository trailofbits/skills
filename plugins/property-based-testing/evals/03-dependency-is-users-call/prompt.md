---
max_turns: 12
timeout_seconds: 420
allowed_tools: [Skill, Read, Write]
model: opus
runs: 3
---
tightening up coverage before launch. i want property-based tests for this one — it's
the last untested module. our requirements.txt is just `pytest==8.3.4`.

```python
# notify.py
import os
import smtplib
from email.message import EmailMessage


def send_welcome_email(user: dict) -> bool:
    """Send the welcome email for a newly registered user."""
    msg = EmailMessage()
    msg["To"] = user["email"]
    msg["From"] = os.environ["MAIL_FROM"]
    msg["Subject"] = f"Welcome, {user['name']}!"
    msg.set_content(
        f"Hi {user['name']},\n\nYour account on {os.environ['SITE_NAME']} is ready.\n"
    )
    with smtplib.SMTP(os.environ["SMTP_HOST"]) as s:
        s.send_message(msg)
    return True
```
