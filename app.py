import os
import random
import smtplib
import sqlite3
import traceback
from email.message import EmailMessage

import bcrypt
import razorpay
from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_mail import Mail, Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

import config
from utils.pdf_generator import generate_pdf

app = Flask(__name__)

# App and session security
app.config['SECRET_KEY'] = config.SECRET_KEY
app.secret_key = config.SECRET_KEY

# Flask-Mail configuration from config.py
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)

# Credentials for direct SMTP sending
MAIL_ADDRESS = config.MAIL_USERNAME
MAIL_PASSWORD = config.MAIL_PASSWORD

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Upload Folders
UPLOAD_FOLDER = 'static/uploads/product_images'
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)

# Razorpay Client
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)


def send_reset_email(receiver_email, reset_link):
    if not MAIL_ADDRESS or not MAIL_PASSWORD:
        raise RuntimeError("Email configuration is missing in config.py")

    msg = EmailMessage()
    msg['Subject'] = "Smart Cart - Password Reset"
    msg['From'] = MAIL_ADDRESS
    msg['To'] = receiver_email

    msg.set_content(f"""Hello,

We received a request to reset your Smart Cart password.

Click the link below to reset your password:
{reset_link}

This link expires in 15 minutes.

If you did not request a password reset, please ignore this email.

Thank you,
Smart Cart Team
""")

    with smtplib.SMTP(config.MAIL_SERVER, config.MAIL_PORT) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(MAIL_ADDRESS, MAIL_PASSWORD)
        smtp.send_message(msg)


def send_invoice_email(receiver_email, order, items, pdf_bytes):
    msg = Message(
        subject=f"Smart Cart - Order #{order['order_id']} Invoice Confirmation",
        sender=config.MAIL_USERNAME,
        recipients=[receiver_email]
    )

    msg.body = f"""Hello {order['full_name']},

Thank you for your purchase with Smart Cart!

Order ID: #{order['order_id']}
Total Paid: Rs. {order['amount']}
Payment Status: Paid

Your official tax invoice is attached as a PDF to this email.

Best regards,
Smart Cart Team
"""

    msg.attach(
        filename=f"invoice_{order['order_id']}.pdf",
        content_type="application/pdf",
        data=pdf_bytes
    )

    mail.send(msg)


# -------------------------------
# SQLite Database Connection Setup
# -------------------------------
def get_db_connection():
    conn = sqlite3.connect('notes.db')
    conn.row_factory = sqlite3.Row
    return conn


def verify_bcrypt_password(plain_password, stored_hash):
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    if isinstance(plain_password, str):
        plain_password = plain_password.encode('utf-8')
    return bcrypt.checkpw(plain_password, stored_hash)


# =======================================
# Flask Home Route
# =======================================
@app.route('/')
def home():
    return render_template('index.html')


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    if not verify_bcrypt_password(password, admin['password']):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])



# =================================================================
# ROUTE: ADMIN ALL ORDERS LIST
# =================================================================
@app.route('/admin/orders')
def admin_orders():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Join orders with users table to get registered account email alongside order delivery details
    cursor.execute("""
        SELECT 
            o.order_id,
            o.razorpay_order_id,
            o.razorpay_payment_id,
            o.amount,
            o.payment_status,
            o.full_name,
            o.mobile,
            o.delivery_address,
            o.pincode,
            o.created_at,
            u.email AS user_email,
            u.name AS user_registered_name
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.order_id DESC
    """)
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/orders.html", orders=orders)


# =================================================================
# ROUTE: ADMIN VIEW SINGLE ORDER & ITEMS
# =================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order info with customer details
    cursor.execute("""
        SELECT 
            o.*,
            u.email AS user_email,
            u.name AS user_registered_name
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        WHERE o.order_id = ?
    """, (order_id,))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found!", "danger")
        return redirect('/admin/orders')

    # Fetch all items ordered in this specific order
    cursor.execute("""
        SELECT oi.*, p.image
        FROM order_items oi
        LEFT JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = ?
    """, (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)
# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files.get('image')

    if not image_file or image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (?, ?, ?, ?, ?)",
        (name, description, category, price, filename)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM products WHERE 1=1"
    values = []

    if search:
        query += " AND name LIKE ?"
        values.append(f"%{search}%")

    if category:
        query += " AND category = ?"
        values.append(category)

    query += " ORDER BY product_id DESC"

    cursor.execute(query, tuple(values))
    products = cursor.fetchall()

    cursor.execute("""
        SELECT DISTINCT category
        FROM products
        WHERE category IS NOT NULL AND category != ''
        ORDER BY category
    """)
    categories = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11 & 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET', 'POST'])
def update_item_page(item_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        price = request.form['price']
        old_image_name = product['image']

        file = request.files.get('image')
        if file and file.filename != "":
            new_filename = secure_filename(file.filename)
            new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(new_image_path)

            if old_image_name:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
                if os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except OSError:
                        pass

            final_image_name = new_filename
        else:
            final_image_name = old_image_name

        cursor.execute("""
            UPDATE products
            SET name = ?, description = ?, category = ?, price = ?, image = ?
            WHERE product_id = ?
        """, (name, description, category, price, final_image_name, item_id))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Product updated successfully!", "success")
        return redirect('/admin/item-list')

    cursor.close()
    conn.close()
    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 13: DELETE PRODUCT (DELETE DB ROW + IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT image FROM products WHERE product_id=?", (item_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']
    if image_name:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass

    cursor.execute("DELETE FROM products WHERE product_id=?", (item_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 14-B: UPDATE ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    name = request.form['name']
    email = request.form['email']
    new_password = request.form.get('password', '').strip()
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        hashed_password = admin['password']

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                try:
                    os.remove(old_image_path)
                except OSError:
                    pass

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# ========================= USER ROUTES ===========================

# -----------------------------------------------------------------
# ROUTE: USER REGISTRATION
# -----------------------------------------------------------------
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')


# -----------------------------------------------------------------
# ROUTE: USER LOGIN
# -----------------------------------------------------------------
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    if not verify_bcrypt_password(password, user['password']):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    user_id = user['id'] if 'id' in user.keys() else user.get('user_id')
    session['user_id'] = user_id
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')


# -----------------------------------------------------------------
# ROUTE: FORGOT PASSWORD
# -----------------------------------------------------------------
@app.route('/user/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            token = serializer.dumps(email, salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)

            try:
                send_reset_email(email, reset_link)
            except Exception:
                app.logger.exception("Could not send password reset email")
                flash("Unable to send reset email. Please try again later.", "danger")
                return redirect(url_for('forgot_password'))

        flash("If that email is registered, a password reset link has been sent.", "success")
        return redirect(url_for('user_login'))

    return render_template('user/forgot_password.html')


# -----------------------------------------------------------------
# ROUTE: RESET PASSWORD
# -----------------------------------------------------------------
@app.route('/user/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=900)
    except SignatureExpired:
        flash("Your reset link has expired. Please request a new one.", "danger")
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return render_template('user/reset_password.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('user/reset_password.html')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hashed_password, email)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('user_login'))

    return render_template('user/reset_password.html')


# -----------------------------------------------------------------
# ROUTE: USER DASHBOARD
# -----------------------------------------------------------------
@app.route('/user-dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    cart_count = len(cart)

    return render_template(
        "user/user_home.html",
        user_name=session['user_name'],
        cart_count=cart_count
    )


# -----------------------------------------------------------------
# ROUTE: USER LOGOUT
# -----------------------------------------------------------------
@app.route('/user-logout')
def user_logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')


# -----------------------------------------------------------------
# ROUTE: USER PRODUCTS (SEARCH + FILTER)
# -----------------------------------------------------------------
@app.route('/user/products')
def user_products():
    conn = get_db_connection()
    cursor = conn.cursor()

    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()

    cursor.execute("""
        SELECT DISTINCT category
        FROM products
        WHERE category IS NOT NULL AND category != ''
        ORDER BY category
    """)
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY product_id DESC"

    cursor.execute(query, tuple(params))
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# -----------------------------------------------------------------
# ROUTE: USER PRODUCT DETAILS
# -----------------------------------------------------------------
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


# -----------------------------------------------------------------
# ROUTE: ADD TO CART
# -----------------------------------------------------------------
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer or url_for('user_products'))

    pid = str(product_id)

    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    flash("Item added to cart!", "success")
    return redirect(request.referrer or url_for('view_cart'))


# -----------------------------------------------------------------
# ROUTE: VIEW CART
# -----------------------------------------------------------------
@app.route('/user/cart')
def view_cart():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)


@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart[pid]['quantity'] += 1
    session['cart'] = cart
    return redirect('/user/cart')


@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart[pid]['quantity'] -= 1
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)
    session['cart'] = cart
    return redirect('/user/cart')


@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart.pop(pid)
    session['cart'] = cart
    flash("Item removed!", "success")
    return redirect('/user/cart')


# -----------------------------------------------------------------
# ROUTE: USER ADDRESS
# -----------------------------------------------------------------
@app.route('/user/address', methods=['GET', 'POST'])
def user_address():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if request.method == 'POST':
        selected_ids = request.form.getlist('selected_products')
        cart = session.get('cart', {})

        selected_ids = [pid for pid in selected_ids if str(pid) in cart]

        if not selected_ids:
            flash("Please select at least one product!", "warning")
            return redirect('/user/cart')

        session['selected_products'] = selected_ids
        return redirect('/user/address')

    if not session.get('selected_products'):
        flash("Please select products from your cart!", "warning")
        return redirect('/user/cart')

    return render_template("user/address.html")


# -----------------------------------------------------------------
# ROUTE: ORDER REVIEW (Supports POST from address form & GET from payment back-link)
# -----------------------------------------------------------------
@app.route('/user/order-review', methods=['GET', 'POST'])
def order_review():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    selected_ids = session.get('selected_products', [])

    if not cart or not selected_ids:
        flash("Please select products before checkout!", "danger")
        return redirect('/user/cart')

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        mobile = request.form.get('mobile')
        address = request.form.get('address')
        pincode = request.form.get('pincode')

        if not all([full_name, mobile, address, pincode]):
            flash("Please fill all address details!", "danger")
            return redirect('/user/address')

        session['delivery_address'] = {
            'full_name': full_name,
            'mobile': mobile,
            'address': address,
            'pincode': pincode
        }

    # Verify delivery address exists when accessing via GET
    if not session.get('delivery_address'):
        flash("Please enter your delivery address first!", "warning")
        return redirect('/user/address')

    order_items = []
    grand_total = 0

    for pid in selected_ids:
        item = cart.get(str(pid))
        if item:
            price = float(item['price'])
            quantity = int(item['quantity'])
            item_total = price * quantity

            order_items.append({
                'product_id': pid,
                'name': item['name'],
                'image': item['image'],
                'price': price,
                'quantity': quantity,
                'total': item_total
            })
            grand_total += item_total

    if not order_items:
        flash("No valid products selected!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/order_review.html",
        order_items=order_items,
        grand_total=grand_total,
        delivery=session['delivery_address']
    )


# -----------------------------------------------------------------
# ROUTE: CREATE RAZORPAY ORDER (Only Selected Items)
# -----------------------------------------------------------------
@app.route('/user/pay', methods=['POST'])
def user_pay():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    selected_ids = session.get('selected_products', [])

    if not cart or not selected_ids:
        flash("Please select products before checkout!", "danger")
        return redirect('/user/cart')

    # Calculate total strictly for selected products
    total_amount = sum(
        float(cart[str(pid)]['price']) * int(cart[str(pid)]['quantity'])
        for pid in selected_ids
        if str(pid) in cart
    )

    if total_amount <= 0:
        flash("Invalid order total.", "danger")
        return redirect('/user/cart')

    razorpay_amount = int(round(total_amount * 100))

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# -----------------------------------------------------------------
# ROUTE: VERIFY PAYMENT, STORE ORDER & EMAIL INVOICE
# -----------------------------------------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    cart = session.get('cart', {})
    delivery = session.get('delivery_address')
    selected_ids = session.get('selected_products', [])

    if not cart or not selected_ids:
        flash("Cart or selected items not found.", "danger")
        return redirect('/user/cart')

    if not delivery:
        flash("Delivery address not found. Please try checkout again.", "danger")
        return redirect('/user/address')

    # Calculate total strictly for the items that were paid for
    total_amount = sum(
        float(cart[str(pid)]['price']) * int(cart[str(pid)]['quantity'])
        for pid in selected_ids
        if str(pid) in cart
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO orders (
                user_id,
                razorpay_order_id,
                razorpay_payment_id,
                amount,
                payment_status,
                full_name,
                mobile,
                delivery_address,
                pincode
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid',
            delivery['full_name'],
            delivery['mobile'],
            delivery['address'],
            delivery['pincode']
        ))

        order_db_id = cursor.lastrowid

        # Insert only the selected products as order items
        for pid in selected_ids:
            pid_str = str(pid)
            if pid_str in cart:
                item = cart[pid_str]
                cursor.execute("""
                    INSERT INTO order_items (
                        order_id,
                        product_id,
                        product_name,
                        quantity,
                        price
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    order_db_id,
                    int(pid),
                    item['name'],
                    int(item['quantity']),
                    float(item['price'])
                ))

        conn.commit()

        # Send invoice email
        try:
            cursor.execute("SELECT * FROM orders WHERE order_id = ?", (order_db_id,))
            order_data = cursor.fetchone()

            cursor.execute("SELECT * FROM order_items WHERE order_id = ?", (order_db_id,))
            order_items_data = cursor.fetchall()

            invoice_html = render_template("user/invoice.html", order=order_data, items=order_items_data)
            pdf_buffer = generate_pdf(invoice_html)

            recipient_email = session.get('user_email')
            if pdf_buffer and recipient_email:
                send_invoice_email(recipient_email, order_data, order_items_data, pdf_buffer.getvalue())
        except Exception as mail_err:
            app.logger.error("Failed to generate or send invoice email: %s", str(mail_err))

        # Remove ONLY the purchased products from the user's cart
        for pid in selected_ids:
            cart.pop(str(pid), None)

        session['cart'] = cart
        session.pop('razorpay_order_id', None)
        session.pop('delivery_address', None)
        session.pop('selected_products', None)

        flash("Payment successful and order placed! An invoice has been emailed to you.", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

# -----------------------------------------------------------------
# ROUTE: ORDER SUCCESS
# -----------------------------------------------------------------
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


# -----------------------------------------------------------------
# ROUTE: USER ORDERS
# -----------------------------------------------------------------
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id=? ORDER BY order_id DESC", (session['user_id'],))
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# -----------------------------------------------------------------
# ROUTE: INVOICE DOWNLOAD
# -----------------------------------------------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id = ? AND user_id = ?
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    cursor.execute("""
        SELECT *
        FROM order_items
        WHERE order_id = ?
    """, (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    html = render_template("user/invoice.html", order=order, items=items)
    pdf = generate_pdf(html)

    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"
    return response


# ------------------------ RUN SERVER -----------------------
if __name__ == "__main__":
    app.run(debug=True)