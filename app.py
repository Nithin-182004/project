from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
from psycopg2.extras import RealDictCursor
import random
import string
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)
app.secret_key = "supersecretkey"

# PostgreSQL Connection Function
def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="time_capsule",
        user="postgres",
        password="2004",
        port="5432"
    )

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Generate Session Token
def generate_session_token():
    return hashlib.sha256(f"{datetime.now()}{random.random()}".encode()).hexdigest()

# Home Route - Redirect to signup
@app.route('/')
def index():
    # If user is already logged in, go to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    # Otherwise, go to signup page
    return redirect(url_for('signup'))

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        phone = request.form.get('phone_number')
        country_code = request.form.get('country_code', '+91')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        pan_card = request.form.get('pan_card_number')
        dob = request.form.get('date_of_birth')
        
        # Validate date of birth and enforce minimum age (18)
        if not dob:
            flash('Please enter your date of birth.', 'error')
            return redirect(url_for('signup'))
        try:
            dob_dt = datetime.strptime(dob, '%Y-%m-%d').date()
            today = datetime.now().date()
            age = today.year - dob_dt.year - ((today.month, today.day) < (dob_dt.month, dob_dt.day))
            if age < 18:
                flash('You must be at least 18 years old to register.', 'error')
                return redirect(url_for('signup'))
        except ValueError:
            flash('Invalid date of birth format.', 'error')
            return redirect(url_for('signup'))
        try:
            conn = get_connection()
            cur = conn.cursor()
            
            # Check if phone already exists
            cur.execute("SELECT user_id FROM users WHERE phone_number = %s", (phone,))
            if cur.fetchone():
                flash('Phone number already registered!', 'error')
                return redirect(url_for('signup'))
            
            # Insert user
            cur.execute("""
                INSERT INTO users (phone_number, country_code, phone_verified)
                VALUES (%s, %s, FALSE) RETURNING user_id
            """, (phone, country_code))
            user_id = cur.fetchone()[0]
            
            # Insert profile
            cur.execute("""
                INSERT INTO user_profiles 
                (user_id, full_name, email, pan_card_number, date_of_birth)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, full_name, email, pan_card, dob))
            
            # Generate OTP
            otp = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)
            cur.execute("""
                INSERT INTO otp_verifications 
                (user_id, phone_number, otp_code, otp_type, expires_at)
                VALUES (%s, %s, %s, 'signup', %s)
            """, (user_id, phone, otp, expires_at))
            
            conn.commit()
            cur.close()
            conn.close()
            
            # Store OTP in session (in real app, send via SMS)
            session['signup_otp'] = otp
            session['temp_user_id'] = user_id
            session['temp_phone'] = phone
            
            flash(f'Signup successful! OTP: {otp} (expires in 5 min)', 'success')
            return redirect(url_for('verify_otp'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

# OTP Verification
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('signup_otp')
        user_id = session.get('temp_user_id')
        
        if entered_otp == stored_otp:
            try:
                conn = get_connection()
                cur = conn.cursor()
                
                # Mark phone as verified
                cur.execute("""
                    UPDATE users SET phone_verified = TRUE 
                    WHERE user_id = %s
                """, (user_id,))
                
                # Mark OTP as verified
                cur.execute("""
                    UPDATE otp_verifications 
                    SET is_verified = TRUE, verified_at = %s
                    WHERE user_id = %s AND otp_code = %s
                """, (datetime.now(), user_id, entered_otp))
                
                conn.commit()
                cur.close()
                conn.close()
                
                flash('Phone verified successfully! You can now login.', 'success')
                session.pop('signup_otp', None)
                session.pop('temp_user_id', None)
                return redirect(url_for('login'))
                
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
        else:
            flash('Invalid OTP!', 'error')
    
    return render_template('verify_otp.html')


@app.route('/resend-signup-otp')
def resend_signup_otp():
    # Resend OTP for signup flow using temp_user_id and temp_phone stored in session
    user_id = session.get('temp_user_id')
    phone = session.get('temp_phone')
    if not user_id or not phone:
        flash('No signup in progress to resend OTP for.', 'error')
        return redirect(url_for('signup'))

    try:
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=5)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO otp_verifications (user_id, phone_number, otp_code, otp_type, expires_at)
            VALUES (%s, %s, %s, 'signup', %s)
        """, (user_id, phone, otp, expires_at))
        conn.commit()
        cur.close()
        conn.close()

        session['signup_otp'] = otp
        flash(f'OTP resent: {otp} (expires in 5 min)', 'success')
    except Exception as e:
        flash(f'Error resending OTP: {str(e)}', 'error')

    return redirect(url_for('verify_otp'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get('phone_number')
        
        try:
            conn = get_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Check if user exists
            cur.execute("""
                SELECT user_id, phone_verified, status 
                FROM users WHERE phone_number = %s
            """, (phone,))
            user = cur.fetchone()
            
            if not user:
                flash('Phone number not registered!', 'error')
                # Log failed attempt
                cur.execute("""
                    INSERT INTO login_history 
                    (phone_number, login_status, failure_reason, ip_address)
                    VALUES (%s, 'failed', 'User not found', %s)
                """, (phone, request.remote_addr))
                conn.commit()
                return redirect(url_for('login'))
            
            if not user['phone_verified']:
                flash('Please verify your phone first!', 'error')
                return redirect(url_for('login'))
            
            if user['status'] != 'active':
                flash('Account is suspended or inactive!', 'error')
                return redirect(url_for('login'))
            
            # Generate login OTP
            otp = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)
            cur.execute("""
                INSERT INTO otp_verifications 
                (user_id, phone_number, otp_code, otp_type, expires_at)
                VALUES (%s, %s, %s, 'login', %s)
            """, (user['user_id'], phone, otp, expires_at))
            
            conn.commit()
            cur.close()
            conn.close()
            
            session['login_otp'] = otp
            session['login_user_id'] = user['user_id']
            session['login_phone'] = phone
            
            flash(f'Login OTP: {otp} (expires in 5 min)', 'success')
            return redirect(url_for('verify_login_otp'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('login.html')

# Verify Login OTP
@app.route('/verify-login-otp', methods=['GET', 'POST'])
def verify_login_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('login_otp')
        user_id = session.get('login_user_id')
        
        if entered_otp == stored_otp:
            try:
                conn = get_connection()
                cur = conn.cursor()
                
                # Create session
                session_token = generate_session_token()
                expires_at = datetime.now() + timedelta(days=30)
                
                cur.execute("""
                    INSERT INTO user_sessions 
                    (user_id, session_token, device_type, ip_address, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, session_token, 'web', request.remote_addr, expires_at))
                
                # Log successful login
                cur.execute("""
                    INSERT INTO login_history 
                    (user_id, phone_number, login_status, ip_address)
                    VALUES (%s, %s, 'success', %s)
                """, (user_id, session.get('login_phone'), request.remote_addr))
                
                # Update last seen
                cur.execute("""
                    UPDATE users SET last_seen = %s WHERE user_id = %s
                """, (datetime.now(), user_id))
                
                conn.commit()
                cur.close()
                conn.close()
                
                session['user_id'] = user_id
                session['session_token'] = session_token
                session.pop('login_otp', None)
                session.pop('login_user_id', None)
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
        else:
            flash('Invalid OTP!', 'error')
    
    return render_template('verify_login_otp.html')


@app.route('/resend-login-otp')
def resend_login_otp():
    user_id = session.get('login_user_id')
    phone = session.get('login_phone')
    if not user_id or not phone:
        flash('No login in progress to resend OTP for.', 'error')
        return redirect(url_for('login'))

    try:
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=5)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO otp_verifications (user_id, phone_number, otp_code, otp_type, expires_at)
            VALUES (%s, %s, %s, 'login', %s)
        """, (user_id, phone, otp, expires_at))
        conn.commit()
        cur.close()
        conn.close()

        session['login_otp'] = otp
        flash(f'Login OTP resent: {otp} (expires in 5 min)', 'success')
    except Exception as e:
        flash(f'Error resending login OTP: {str(e)}', 'error')

    return redirect(url_for('verify_login_otp'))

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    try:
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get user profile
        cur.execute("""
            SELECT u.*, p.* FROM users u
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            WHERE u.user_id = %s
        """, (session['user_id'],))
        user = cur.fetchone()
        
        # Get active sessions
        cur.execute("""
            SELECT * FROM user_sessions 
            WHERE user_id = %s AND is_active = TRUE
            ORDER BY last_activity DESC
        """, (session['user_id'],))
        sessions = cur.fetchall()
        
        # Get login history
        cur.execute("""
            SELECT * FROM login_history 
            WHERE user_id = %s 
            ORDER BY attempted_at DESC LIMIT 10
        """, (session['user_id'],))
        login_logs = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return render_template('dashboard.html', 
                             user=user, 
                             sessions=sessions,
                             login_logs=login_logs)
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('signup'))

# View All Users (Admin)
@app.route('/users')
def view_users():
    try:
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT u.*, p.full_name, p.email, p.pan_card_number 
            FROM users u
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            ORDER BY u.created_at DESC
        """)
        users = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return render_template('users.html', users=users)
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))

# Logout
@app.route('/logout')
def logout():
    if 'user_id' in session and 'session_token' in session:
        try:
            conn = get_connection()
            cur = conn.cursor()
            
            # Deactivate session
            cur.execute("""
                UPDATE user_sessions 
                SET is_active = FALSE 
                WHERE session_token = %s
            """, (session['session_token'],))
            
            conn.commit()
            cur.close()
            conn.close()
        except:
            pass
    
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('signup'))

if __name__ == '__main__':
    app.run(debug=True)