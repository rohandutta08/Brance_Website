import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import os
import sqlite3

# Optional: Use environment variables for secrets
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS") or "rohandutta3200@gmail.com"
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD") or "Payal@0809"

def generate_otp(length=6):
    return ''.join(str(random.randint(0, 9)) for _ in range(length))


def send_email_otp(to_email, otp):
    try:
        subject = "Your Email Verification OTP"
        body = f"Your OTP for email verification is: {otp}"

        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        print(body)

        msg.attach(MIMEText(body, 'plain'))

        # Setup SMTP server (e.g. Gmail SMTP)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print(f"Sent email OTP to {to_email}")
        return True
    except Exception as e:
        print("Failed to send email:", e)
        return False


import smtplib
from email.mime.text import MIMEText

def send_verification_email(receiver_email, otp):
    sender_email = "rohandutta3200@gmail.com"
    app_password = "yngq pvwo vjvy pnij"  # not your regular password

    subject = "Verify Your Email"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print("Failed to send email:", e)



def send_sms_otp(phone_number, otp):
    try:
        # ⚠️ Example Only: Replace with real SMS API like Twilio, Fast2SMS, etc.
        print(f"Mock SMS sent to {phone_number}: Your OTP is {otp}")
        return True
    except Exception as e:
        print("Failed to send SMS:", e)
        return False

def update_email_verification(email):
    # conn = sqlite3.connect('database.db')
    # c = conn.cursor()
    # c.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (email,))
    # conn.commit()
    # conn.close()
    with sqlite3.connect("database.db") as conn:
        # cursor = conn.cursor()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (email,))
        conn.commit()
        # conn.close()