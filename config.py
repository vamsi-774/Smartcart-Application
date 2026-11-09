# import sqlite3

# conn = sqlite3.connect("notes.db")
import os
from dotenv import load_dotenv

load_dotenv()

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

SECRET_KEY = "abc123"

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'vamsicheekati774@gmail.com'
MAIL_PASSWORD = 'wxqofzfnpefbvzil'




