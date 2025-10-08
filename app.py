from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import random
import string
from datetime import datetime, timedelta
import hashlib
import os

app = Flask(__name__)
# Use environment variable for secret key to avoid committing secrets in source
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')

# PostgreSQL Connection Function
def get_connection():
    # Read DB config from environment where possible
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_name = os.environ.get('DB_NAME', 'time_capsule')
    db_user = os.environ.get('DB_USER', 'postgres')
    db_password = os.environ.get('DB_PASSWORD', '2004')
    db_port = int(os.environ.get('DB_PORT', 5432))
    return psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port=db_port
    )

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_email_via_sendgrid(to_email, otp):
    """Send the OTP to the given email using SendGrid.

    This function requires the environment variable SENDGRID_API_KEY be set.
    Optionally set SENDGRID_FROM_EMAIL to control the sender address.
    """
    api_key = os.environ.get('SENDGRID_API_KEY')
    from_email = os.environ.get('SENDGRID_FROM_EMAIL', 'noreply@example.com')
    if not api_key:
        raise RuntimeError('SENDGRID_API_KEY not configured')

    # Import inside the function to avoid import errors when the package isn't installed
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail

    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject='Your verification code',
        html_content=f'<p>Your verification code is <strong>{otp}</strong>. It expires in 5 minutes.</p>'
    )

    sg = SendGridAPIClient(api_key)
    response = sg.send(message)
    return response

# Send Phone OTP
@app.route('/send-phone-otp', methods=['POST'])
def send_phone_otp():
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Invalid request format'
        }), 400

    data = request.get_json()
    phone = data.get('phone_number')
    country_code = data.get('country_code', '+91')

    if not phone:
        return jsonify({
            'success': False,
            'message': 'Phone number is required'
        }), 400

    try:
        # Check if phone is already registered
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM users WHERE phone_number = %s", (phone,))
        if cur.fetchone():
            return jsonify({
                'success': False,
                'message': 'Phone number is already registered'
            }), 400

        # Generate and store OTP
        otp = generate_otp()
        now = datetime.now()
        
        session['signup_phone_otp'] = otp
        session['temp_phone'] = phone
        session['temp_country_code'] = country_code
        session['phone_otp_generated_at'] = now.isoformat()

        # In a real application, send OTP via SMS
        # For demo, we'll show it in response
        return jsonify({
            'success': True,
            'message': f'OTP sent successfully: {otp}'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Send Email OTP
@app.route('/send-email-otp', methods=['POST'])
def send_email_otp():
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Invalid request format'
        }), 400

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({
            'success': False,
            'message': 'Email address is required'
        }), 400

    try:
        # Check if email is already registered
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM user_profiles WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({
                'success': False,
                'message': 'Email address is already registered'
            }), 400

        # Generate and store OTP
        otp = generate_otp()
        now = datetime.now()
        
        session['signup_email_otp'] = otp
        session['temp_email'] = email
        session['email_otp_generated_at'] = now.isoformat()

        # Try to send via SendGrid if configured, otherwise return OTP in response for local testing
        try:
            resp = send_email_via_sendgrid(email, otp)
            return jsonify({
                'success': True,
                'message': 'OTP sent via SendGrid'
            })
        except Exception as ex:
            # Fallback: return OTP in response so devs can test without SendGrid
            return jsonify({
                'success': True,
                'message': f'OTP sent successfully: {otp}',
                'warning': str(ex)
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Phone OTP Verification
@app.route('/verify-phone-otp', methods=['POST'])
def verify_phone_otp():
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Invalid request format'
        }), 400

    data = request.get_json()
    entered_otp = data.get('phone_otp')
    stored_otp = session.get('signup_phone_otp')
    phone = session.get('temp_phone')
    
    # Clear expired OTP if exists
    if 'phone_otp_generated_at' in session:
        otp_age = datetime.now() - datetime.fromisoformat(session['phone_otp_generated_at'])
        if otp_age.total_seconds() > 300:  # 5 minutes
            session.pop('signup_phone_otp', None)
            session.pop('phone_otp_generated_at', None)
            stored_otp = None
    
    if not phone or not stored_otp:
        return jsonify({
            'success': False,
            'message': 'No phone verification in progress or OTP expired.'
        }), 400
    
    if entered_otp == stored_otp:
        try:
            # Store verification status in session
            session['phone_verified'] = True
            # Clear OTP data
            session.pop('signup_phone_otp', None)
            session.pop('phone_otp_generated_at', None)
            
            return jsonify({
                'success': True,
                'message': 'Phone number verified successfully!'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid OTP'
        }), 400

# Email OTP Verification
@app.route('/verify-email-otp', methods=['POST'])
def verify_email_otp():
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Invalid request format'
        }), 400

    data = request.get_json()
    entered_otp = data.get('email_otp')
    stored_otp = session.get('signup_email_otp')
    email = session.get('temp_email')
    
    # Clear expired OTP if exists
    if 'email_otp_generated_at' in session:
        otp_age = datetime.now() - datetime.fromisoformat(session['email_otp_generated_at'])
        if otp_age.total_seconds() > 300:  # 5 minutes
            session.pop('signup_email_otp', None)
            session.pop('email_otp_generated_at', None)
            stored_otp = None
    
    if not email or not stored_otp:
        return jsonify({
            'success': False,
            'message': 'No email verification in progress or OTP expired.'
        }), 400

    # Check if the OTP is expired (5 minutes)
    if entered_otp == stored_otp:
        try:
            # Store verification status in session
            session['email_verified'] = True
            # Clear OTP data
            session.pop('signup_email_otp', None)
            session.pop('email_otp_generated_at', None)
            
            return jsonify({
                'success': True,
                'message': 'Email address verified successfully!'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid OTP'
        }), 400

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
        # Get form data
        phone = request.form.get('phone_number')
        country_code = request.form.get('country_code', '+91')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        pan_card = request.form.get('pan_card_number')
        dob = request.form.get('date_of_birth')
        
        # Make email mandatory
        if not email:
            flash('Email address is required for registration.', 'error')
            return redirect(url_for('signup'))
        
        # Verify both phone and email are verified
        if not session.get('phone_verified'):
            flash('Please verify your phone number first.', 'error')
            return redirect(url_for('signup'))
            
        if not session.get('email_verified'):
            flash('Please verify your email address first.', 'error')
            return redirect(url_for('signup'))
            
        # Verify the phone and email match the verified ones
        if phone != session.get('temp_phone'):
            flash('Please verify the new phone number.', 'error')
            return redirect(url_for('signup'))
            
        if email != session.get('temp_email'):
            flash('Please verify the new email address.', 'error')
            return redirect(url_for('signup'))
            
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
            
            # Insert user with verified phone
            cur.execute("""
                INSERT INTO users (phone_number, country_code, phone_verified)
                VALUES (%s, %s, TRUE) RETURNING user_id
            """, (phone, country_code))
            user_id = cur.fetchone()[0]
            
            # Insert profile with verified email
            cur.execute("""
                INSERT INTO user_profiles 
                (user_id, full_name, email, pan_card_number, date_of_birth, email_verified)
                VALUES (%s, %s, %s, %s, %s, TRUE)
            """, (user_id, full_name, email, pan_card, dob))
            
            # Record verifications
            now = datetime.now()
            cur.execute("""
                INSERT INTO otp_verifications 
                (user_id, phone_number, otp_type, expires_at, is_verified, verified_at)
                VALUES (%s, %s, 'signup', %s, TRUE, %s)
            """, (user_id, phone, now + timedelta(minutes=5), now))
            
            cur.execute("""
                INSERT INTO otp_verifications 
                (user_id, phone_number, otp_type, expires_at, is_verified, verified_at)
                VALUES (%s, %s, 'email', %s, TRUE, %s)
            """, (user_id, email, now + timedelta(minutes=5), now))
            
            conn.commit()
            cur.close()
            conn.close()
            
            # Clear all verification session data
            session.pop('signup_phone_otp', None)
            session.pop('phone_otp_generated_at', None)
            session.pop('temp_phone', None)
            session.pop('temp_country_code', None)
            session.pop('phone_verified', None)
            session.pop('signup_email_otp', None)
            session.pop('email_otp_generated_at', None)
            session.pop('temp_email', None)
            session.pop('email_verified', None)
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if it's JSON request (AJAX)
        if request.is_json:
            data = request.get_json()
            phone = data.get('phone_number')
        else:
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
                # Log failed attempt
                cur.execute("""
                    INSERT INTO login_history 
                    (phone_number, login_status, failure_reason, ip_address)
                    VALUES (%s, 'failed', 'User not found', %s)
                """, (phone, request.remote_addr))
                conn.commit()
                
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'message': 'Phone number not registered!'
                    }), 400
                flash('Phone number not registered!', 'error')
                return redirect(url_for('login'))
            
            if not user['phone_verified']:
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'message': 'Please verify your phone first!'
                    }), 400
                flash('Please verify your phone first!', 'error')
                return redirect(url_for('login'))
            
            if user['status'] != 'active':
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'message': 'Account is suspended or inactive!'
                    }), 400
                flash('Account is suspended or inactive!', 'error')
                return redirect(url_for('login'))
            
            # Generate login OTP
            otp = generate_otp()
            now = datetime.now()
            expires_at = now + timedelta(minutes=5)
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
            session['login_otp_generated_at'] = now.isoformat()
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': f'Login OTP: {otp} (expires in 5 min)',
                    'expires_in': 300
                })
            
            flash(f'Login OTP: {otp} (expires in 5 min)', 'success')
            return redirect(url_for('verify_login_otp'))
            
        except Exception as e:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': f'Error: {str(e)}'
                }), 500
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('login.html')

# Verify Login OTP
@app.route('/verify-login-otp', methods=['POST'])
def verify_login_otp():
    # Check if it's JSON request (AJAX)
    if request.is_json:
        data = request.get_json()
        entered_otp = data.get('otp')
    else:
        entered_otp = request.form.get('otp')
        
    stored_otp = session.get('login_otp')
    user_id = session.get('login_user_id')
    
    if not user_id:
        if request.is_json:
            return jsonify({
                'success': False,
                'message': 'No login in progress.'
            }), 400
        flash('No login in progress.', 'error')
        return redirect(url_for('login'))

    # Check OTP expiration
    if 'login_otp_generated_at' in session:
        otp_age = datetime.now() - datetime.fromisoformat(session['login_otp_generated_at'])
        if otp_age.total_seconds() > 300:  # 5 minutes
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'OTP has expired. Please request a new one.'
                }), 400
            flash('OTP has expired. Please request a new one.', 'error')
            return redirect(url_for('login'))
    
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
            session.pop('login_otp_generated_at', None)
            session.pop('login_phone', None)
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'Login successful!',
                    'redirect': url_for('dashboard')
                })
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': f'Error: {str(e)}'
                }), 500
            flash(f'Error: {str(e)}', 'error')
    else:
        if request.is_json:
            return jsonify({
                'success': False,
                'message': 'Invalid OTP!'
            }), 400
        flash('Invalid OTP!', 'error')
        return redirect(url_for('login'))

@app.route('/resend-login-otp')
def resend_login_otp():
    user_id = session.get('login_user_id')
    phone = session.get('login_phone')
    if not user_id or not phone:
        return jsonify({
            'success': False,
            'message': 'No login in progress to resend OTP for.'
        }), 400

    try:
        otp = generate_otp()
        now = datetime.now()
        expires_at = now + timedelta(minutes=5)
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
        session['login_otp_generated_at'] = now.isoformat()
        
        return jsonify({
            'success': True,
            'message': f'Login OTP resent: {otp} (expires in 5 min)',
            'expires_in': 300  # 5 minutes in seconds
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error resending OTP: {str(e)}'
        }), 500

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