import requests
from flask import Flask, render_template, redirect, url_for, request, session, flash,abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import random
from email.mime.text import MIMEText
# from pyngrok import ngrok, conf
import socket
from your_email_sms_sender import generate_otp, send_email_otp, send_sms_otp, update_email_verification, send_verification_email
import razorpay
from datetime import datetime

app = Flask(__name__)
app.secret_key = '9f2b123abc21ac14eaf98ddc8fc9013a2379beaad097d8cfd387d1b2cd4a751b'


# Razorpay sandbox credentials
RAZORPAY_KEY_ID = "rzp_test_your_key"
RAZORPAY_KEY_SECRET = "your_secret"
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

EMAIL_ADDRESS = 'rohandutta3200@gmail.com'
EMAIL_PASSWORD = 'Payal@0809'  # Use Gmail App Passwords

@app.route('/add-funds', methods=['GET'])
def add_funds():
    if 'user' not in session:
        return redirect('/login')

    # if request.method == 'POST':
    #     amount = int(float(request.form['amount']) * 100)  # ₹ to paise

    #     payment = client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': '1'})
    #     return render_template('checkout.html', order=payment, key=RAZORPAY_KEY_ID)

    return render_template('add_funds.html')

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user' not in session:
        return redirect('/login')

    amount = float(request.form['amount'])
    username = session['user']

    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        # Update balance in the users table
        cursor.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE username = ?", (amount, username))
        conn.commit()

    return redirect('/profile')

@app.route('/confirm-payment', methods=['POST'])
def confirm_payment():
    if 'user' not in session:
        return redirect('/login')

    amount = float(request.form['amount'])
    username = session['user']

    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE username = ?", (amount, username))
        conn.commit()

    return redirect('/profile')


@app.route('/payment-success', methods=['POST'])
def payment_success():
    data = request.form
    # Validate signature
    try:
        client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        })
    except:
        return abort(400)

    amount = int(data['razorpay_amount']) / 100
    username = session['user']

    with sqlite3.connect("database.db") as conn:
        conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))

    flash('Funds added successfully!', 'success')
    return redirect('/profile')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))
        # email = session.get('email')
        print(session)
        email = session['email']
        if request.method == 'POST':
            entered_otp = request.form.get('otp')
            expected_otp = session.get('email_otp')

            # user_otp = request.form['otp']
            # if user_otp == session.get('email_otp'):
            #     with sqlite3.connect("database.db") as conn:
            #         conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (email,))
            #     flash('Email verified successfully!', 'success')
            #     return redirect(url_for('verify_phone'))
            # else:
            #     flash('Invalid OTP. Please try again.', 'danger')
            if entered_otp == expected_otp:
                # Update user in DB
                update_email_verification(session['email'])

                # Optionally remove OTP from session
                session.pop('email_otp', None)

                return redirect(url_for('dashboard'))
            else:
                return "Invalid OTP. Try again.", 400
        else:
            otp = generate_otp()
            session["email_otp"] = otp
            send_verification_email(email, otp)

        # Send OTP only on GET or first-time POST
        if 'email_otp' not in session:
            otp = str(random.randint(100000, 999999))
            session['email_otp'] = otp
            send_verification_email(email, otp)

        return render_template("verify_email.html", email=email)
    except Exception as e:
        print(str(e))
        pass

@app.route('/verify-phone', methods=['GET', 'POST'])
def verify_phone():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))
        # phone = session.get('phone')
        print(session)
        phone = session['phone']
        # if request.method == 'POST':
        #     user_otp = request.form['otp']
        #     if user_otp == session.get('phone_otp'):
        #         with sqlite3.connect("database.db") as conn:
        #             conn.execute("UPDATE users SET phone_verified = 1 WHERE phone = ?", (phone,))
        #         flash('Phone number verified successfully!', 'success')
        #         return redirect(url_for('dashboard'))
        #     else:
        #         flash('Invalid OTP. Please try again.', 'danger')

        # # Send OTP only on GET or first-time POST
        # if 'phone_otp' not in session:
        #     otp = str(random.randint(100000, 999999))
        #     session['phone_otp'] = otp
        #     send_sms_otp(phone, otp)
        if request.method == 'POST':
        # Step 2: User submitted the OTP
            user = session['user']
            entered_otp = request.form.get('otp')
            correct_otp = session.get('phone_otp')

            if entered_otp == correct_otp:
                # Mark phone as verified in DB (you should implement this)
                # user = session['user']
                # db = get_db()
                # db.execute("UPDATE users SET phone_verified = 1 WHERE username = ?", (user,))
                # db.commit()
                with sqlite3.connect("database.db") as conn:
                    # cursor = conn.cursor()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET phone_verified = 1 WHERE username = ?", (user,))
                    conn.commit()

                flash('Phone number verified successfully!', 'success')
                return redirect('/dashboard')
            else:
                flash('Incorrect OTP. Please try again.', 'danger')

        else:
            # Step 1: Generate OTP and send
            user = session['user']
            # db = get_db()
            # user_data = db.execute("SELECT phone FROM users WHERE username = ?", (user,)).fetchone()
            with sqlite3.connect("database.db") as conn:
                # cursor = conn.cursor()
                cursor = conn.cursor()
                user_data = cursor.execute("SELECT phone FROM users WHERE username = ?", (user,)).fetchone()
            if not user_data or not user_data[0]:
                flash("No phone number found. Please update your profile.", "danger")
                return redirect('/profile')

            phone_number = user_data[0]
            otp = str(random.randint(100000, 999999))
            session['phone_otp'] = otp
            send_sms(phone_number, otp)

    # return render_template('verify_phone.html')

        return render_template("verify_phone.html", phone=phone)
    except Exception as e:
        print(str(e))
        pass

def send_sms(phone_number, otp):
    print(f"Sending OTP {otp} to phone {phone_number}")

def send_otp_email(to_email, otp):
    msg = MIMEText(f"Your OTP code is: {otp}")
    msg['Subject'] = "Brnance - Password Reset OTP"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print("Email error:", e)

# Initialize SQLite DB
def init_db():
    with sqlite3.connect("database.db") as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            phone TEXT,
            password TEXT,
            email_verified INTEGER,
            phone_verified INTEGER,
            balance INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS trades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            coin TEXT,
            amount REAL,
            price REAL,
            total REAL
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            symbol TEXT,
            price REAL,
            added_at TEXT
        )''')

def get_crypto_prices(limit=100):
    try:
        url = "https://api.coingecko.com/api/v3/coins/markets"
        params = {
            "vs_currency": "usd",
            "order": "market_cap_desc",
            "per_page": limit,
            "page": 1,
            "sparkline": "false"
        }
        response = requests.get(url, params=params)
        data = response.json()

        prices = {}
        for coin in data:
            symbol = coin['symbol'].upper()
            prices[symbol] = {
                "name": coin['name'],
                "price": coin['current_price'],
                "change": coin['price_change_percentage_24h'],
                "image": coin['image']
            }

        return prices
    except Exception as e:
        print(str(e))
        

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            email = request.form['email']
            phone = request.form['phone']
            username = request.form['username']
            password = generate_password_hash(request.form['password'])

            with sqlite3.connect('database.db') as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (email, phone, username, password, email_verified, phone_verified, balance) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (email, phone, username, password, 0, 0,0))
                prices = get_crypto_prices()

                # Default coins to add to watchlist
                default_symbols = ['BTC', 'ETH', 'BNB']
                now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

                for symbol in default_symbols:
                    if symbol in prices:
                        price = prices[symbol]['price']
                        cursor.execute("""
                            INSERT INTO watchlist (username, symbol, price, added_at)
                            VALUES (?, ?, ?, ?)
                        """, (username, symbol, price, now))
                # cursor.execute("""
                #             INSERT INTO trades (username)
                #             VALUES (?)
                #         """, (username,))
                # Insert dummy trades
                for symbol in default_symbols:
                    if symbol in prices:
                        price = prices[symbol]['price']
                        amount = 0.01  # Default example
                        total = round(price * amount, 2)
                        action = 'buy'
                        cursor.execute("""
                            INSERT INTO trades (username, action, coin, amount, price, total)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (username, action, symbol, amount, price, total))

            return redirect(url_for('login'))

        return render_template('register.html')
    except Exception as e:
        print(str(e))
        pass

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    # user_id = session['user_id']
    try:
        email = request.form['email']
        phone = request.form['phone']
        username = request.form['username']
        # password = request.form['password']

        # Example using SQLAlchemy
        # user = User.query.get(user_id)
        with sqlite3.connect("database.db") as conn:
            # cursor = conn.cursor()
            cursor = conn.cursor()
            cursor.execute("Update users set email=?, phone=?, username=?",
                            (email, phone, username))
            conn.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    except Exception as e:
        print(str(e))

@app.route('/login', methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            
            username = request.form['username']
            password = request.form['password']
            # email = request.form['email']

            with sqlite3.connect("database.db") as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                if user and check_password_hash(user[4], password):
                    session['user'] = username
                    session['email'] = user[2]
                    session['phone'] = user[3]
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('invalid.html')
        # else:
            # return render_template('dashboard.html')
        return render_template('login.html')
    except:
        return render_template('invalid.html')

# Support Page
@app.route('/support')
def support():
    return render_template('support.html')

# Privacy Policy Page
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# About Us Page
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/add_watchlist/<symbol>')
def add_watchlist(symbol):
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    prices = get_crypto_prices()
    coin = prices.get(symbol.upper())

    if symbol not in prices:
        flash("Invalid")

    # current_price = prices[symbol]['price']
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM watchlist WHERE user = ? AND symbol = ?", (session['user'], symbol.upper()))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO watchlist (user, symbol, price) VALUES (?, ?, ?)",
                (session['user'], symbol.upper(), coin['price'])
            )
            conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/remove_watchlist/<symbol>')
def remove_watchlist(symbol):
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM watchlist WHERE user = ? AND symbol = ?", (user, symbol))
        conn.commit()

    return redirect(url_for('dashboard'))


def get_db():
    return sqlite3.connect('database.db')

# --- Display Watchlist ---
@app.route('/watchlist')
def watchlist():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    prices = get_crypto_prices()

    db = get_db()
    cursor = db.cursor()
    rows = cursor.execute("SELECT symbol, price FROM watchlist WHERE username = ?", (user,))
    # symbols = [row[0] for row in cursor.fetchall()]
    # price = [row[1] for row in cursor.fetchall()]
    

    # Dummy coin data for illustration
    # all_coins = get_crypto_prices()
    #{
    #     'BTC': {'name': 'Bitcoin'},
    #     'ETH': {'name': 'Ethereum'},
    #     'DOGE': {'name': 'Dogecoin'},
    #     'SOL': {'name': 'Solana'},
    #     # Add more if needed
    # }

    # watchlist_coins = {sym: all_coins.get(sym, {}) for sym in symbols}
    coins = {}
    for symbol, price in rows:
        current = prices.get(symbol.upper())
        if current:
            coins[symbol] = {
                'name': current['name'],
                'current_price': current['price'],
                'price_at_addition': price
            }
    db.close()
    return render_template('watchlist.html', coins=coins)

@app.route('/profile')
def profile():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))

        username = session['user']
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            user = cursor.execute("SELECT username, email, phone, created_at, balance FROM users WHERE username = ?", (username,)).fetchone()
            trades = cursor.execute("SELECT * FROM trades WHERE username = ? ORDER BY id DESC LIMIT 5", (username,)).fetchall()

        if user:
            user_data = {
                "username": user[0],
                "email": user[1],
                "phone": user[2],
                "created_at": user[3],
                "balance": user[4],
                "recent_trades": trades
            }
            return render_template("profile.html", user=user_data)

        # return "User not found"
        else:
            return render_template('invalid.html')
    except Exception as e:
        print(str(e))
        pass



@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email_verified, phone_verified FROM users WHERE username = ?", (user,))
        user_data = cursor.fetchone()

        if not user_data:
            return redirect(url_for('login'))

        username, email_verified, phone_verified = user_data

        # Fetch user's watchlist symbols
        cursor.execute("SELECT symbol FROM watchlist WHERE username = ?", (user,))
        watchlist_rows = cursor.fetchall()
        watchlist = [row[0] for row in watchlist_rows]

    # Example crypto prices
    prices = get_crypto_prices()  # Assuming this returns a dictionary

    if prices is None:
        prices = {}
    
    return render_template("dashboard.html",
                           user=username,
                           prices=prices,
                           email_verified=email_verified,
                           phone_verified=phone_verified,
                           watchlist=watchlist)

@app.route('/trade', methods=['GET', 'POST'])
def trade():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM users WHERE username = ?", (session['user'],))
        row = cursor.fetchone()
        balance = row[0] if row else 0
        if request.method == 'POST':
            action = request.form['action']
            coin = request.form['coin']
            amount = float(request.form['amount'])

            prices = get_crypto_prices()
            price = prices.get(coin, {}).get('price', 0)
            total = round(price * amount, 2)

            # with sqlite3.connect("database.db") as conn:
            #     conn.execute(
            #         "INSERT INTO trades (username, action, coin, amount, price, total) VALUES (?, ?, ?, ?, ?, ?)",
            #         (session['user'], action, coin, amount, price, total)
            #     )
            
            
            if action == 'buy':
                if balance < total:
                    conn.close()
                    flash("Insufficient Fund", "danger")
                    return redirect('/trade')
                    # return "Insufficient balance", 400
                # Deduct balance
                balance -= total
                cursor.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (total, session['user']))
            elif action == 'sell':
                balance += total
                # For simplicity, we’ll credit the balance for sells (assumes user has the coin)
                cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (total, session['user']))
            else:
                conn.close()
                flash("Insufficient Fund", "danger")
                return redirect('/trade')
                # return "Invalid action", 400

            # Log trade
            cursor.execute(
                "INSERT INTO trades (username, action, coin, amount, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                (session['user'], action, coin, amount, price, total)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('trade'))

        # For GET request
        prices = get_crypto_prices()  # Dict of { "BTC": {name, price, change, image}, ... }
        with sqlite3.connect("database.db") as conn:
            trades = conn.execute("SELECT * FROM trades WHERE username = ?", (session['user'],)).fetchall()

        return render_template('trade.html', balance = balance, user=session['user'], prices=prices, trades=trades)
    except Exception as e:
        print(str(e))
        pass

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/forgot', methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form['email']
        with sqlite3.connect("database.db") as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['reset_email'] = email
            send_otp_email(email, otp)
            return redirect(url_for('verify_otp'))
        else:
            return "Email not registered."
    return render_template("forgot.html")

@app.route('/verify-otp', methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered = request.form['otp']
        if entered == session.get('otp'):
            return redirect(url_for('reset_password'))
        else:
            return "Invalid OTP. Try again."
    return render_template("verify_otp.html")

@app.route('/reset-password', methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        identifier = request.form['identifier'].strip()
        new_password = generate_password_hash(request.form['password'])

        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            # Check if identifier is email or phone
            if "@" in identifier:
                cursor.execute("SELECT id FROM users WHERE email = ?", (identifier,))
            else:
                cursor.execute("SELECT id FROM users WHERE phone = ?", (identifier,))

            user = cursor.fetchone()

            if user:
                # Update password
                if "@" in identifier:
                    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, identifier))
                else:
                    cursor.execute("UPDATE users SET password = ? WHERE phone = ?", (new_password, identifier))

                conn.commit()
                session.pop('otp', None)
                session.pop('reset_email', None)
                return redirect(url_for('login'))
            else:
                flash("No account found with that email or phone number.", "danger")

    return render_template("reset_password.html")


@app.route('/settings', methods=['GET', 'POST'])
# @login_required  # if you're using login sessions
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Capture form values
        notifications = request.form.get('notifications') == 'on'
        currency = request.form.get('currency')
        language = request.form.get('language')
        
        # Save/update settings in DB or session (example using session)
        session['settings'] = {
            'notifications': notifications,
            'currency': currency,
            'language': language
        }

        flash('Settings updated successfully.', 'success')
        return redirect(url_for('settings'))

    # Load current settings (from DB/session)
    default_settings = {
        'notifications': session.get('settings', {}).get('notifications', True),
        'currency': session.get('settings', {}).get('currency', 'USD'),
        'language': session.get('settings', {}).get('language', 'English')
    }
    return render_template('settings.html', settings=default_settings)

if __name__ == "__main__":
    init_db()

    # from pyngrok import ngrok, conf

    # # Set your ngrok auth token
    # conf.get_default().auth_token = "2h8hVm4h8eU4vrlVgyCXZyYjwXG_31bxvzDPmabEAeLGHi1WS"

    # # Open a ngrok tunnel on the default port 5000
    # public_url = ngrok.connect(5000, bind_tls=True)  # TLS for HTTPS
    # print(f"\n🔗 Ngrok Tunnel URL: {public_url}\n")

    # # Optional: make the public URL available in templates
    # app.config["BASE_URL"] = public_url

    # Important: Disable debug mode to avoid multiple reloads
    app.run(host="0.0.0.0", port=5000, debug=False)

