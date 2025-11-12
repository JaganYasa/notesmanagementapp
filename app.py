from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


app = Flask(__name__)
app.secret_key = "myverysecretkey"


def get_db_connection():
    """
    Create and return a new MySQL connection.
    Edit host/user/password/database if yours are different.
    """
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="2851",
        database="notesdb"
    )
    return conn


@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/viewall')
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # If POST -> process registration form
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Basic checks (non-empty)
        if not username or not email or not password:
            flash("Please fill all fields.", "danger")
            return redirect('/register')

        # Hash the password before saving
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        exists = cur.fetchone()
        if exists:
            # Close connection and inform user
            cur.close()
            conn.close()
            flash("Username already taken. Choose another.", "danger")
            return redirect('/register')

        # Insert new user into users table
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    # If GET -> show registration form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If POST -> authenticate
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Basic check
        if not username or not password:
            flash("Please enter username and password.", "danger")
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Check whether user exists and password matches
        if user and check_password_hash(user['password'], password):
            # Save user id and username in session for future access control
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"Welcome, {user['username']}!", "success")
            return redirect('/viewall')
        else:
            flash("Invalid username or password.", "danger")
            return redirect('/login')

    # If GET -> show login page
    return render_template('login.html')


@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/login')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            # Generate a reset token
            reset_token = secrets.token_urlsafe(32)
            # Store the token in session or database (for simplicity, using session)
            session['reset_token'] = reset_token
            session['reset_email'] = email

            # Send email with reset link
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_reset_email(email, reset_link)
            flash('A password reset link has been sent to your email.', 'info')
            return redirect('/login')
        else:
            flash('Email not found.', 'error')
            return render_template('forgot_password.html')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'reset_token' not in session or session['reset_token'] != token:
        flash('Invalid or expired reset token.', 'error')
        return redirect('/login')

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        hashed_password = generate_password_hash(new_password)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, session['reset_email']))
        conn.commit()
        cur.close()
        conn.close()

        # Clear session
        session.pop('reset_token', None)
        session.pop('reset_email', None)
        flash('Password has been reset successfully.', 'success')
        return redirect('/login')
    return render_template('reset_password.html')


@app.route('/addnote', methods=['GET', 'POST'])
def addnote():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        user_id = session['user_id']

        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect('/addnote')

        conn = get_db_connection()
        cur = conn.cursor()
        # Save note with user_id to keep notes private
        cur.execute("INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s)",
                    (title, content, user_id))
        conn.commit()
        cur.close()
        conn.close()

        flash("Note added successfully.", "success")
        return redirect('/viewall')

    # GET -> show add note form
    return render_template('addnote.html')


@app.route('/viewall')
def viewall():
    # Ensure user logged in
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    search_query = request.args.get('search', '').strip()

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    if search_query:
        # Search in title or content
        cur.execute("SELECT id, title, content, created_at FROM notes WHERE user_id = %s AND (title LIKE %s OR content LIKE %s) ORDER BY created_at DESC", (user_id, f'%{search_query}%', f'%{search_query}%'))
    else:
        # Fetch only notes that belong to this user
        cur.execute("SELECT id, title, content, created_at FROM notes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    notes = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('viewnotes.html', notes=notes, search_query=search_query)


@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    # Select note only if it belongs to current user
    cur.execute("SELECT id, title, content, created_at FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cur.fetchone()
    cur.close()
    conn.close()

    if not note:
        # Either note doesn't exist or doesn't belong to the user
        flash("You don't have access to this note.", "danger")
        return redirect('/viewall')

    return render_template('singlenote.html', note=note)


@app.route('/updatenote/<int:note_id>', methods=['GET', 'POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Check existence and ownership
    cur.execute("SELECT id, title, content FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cur.fetchone()

    if not note:
        cur.close()
        conn.close()
        flash("You are not authorized to edit this note.", "danger")
        return redirect('/viewall')

    if request.method == 'POST':
        # Get updated data
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect(url_for('updatenote', note_id=note_id))

        # Update query guarded by user_id
        cur.execute("UPDATE notes SET title = %s, content = %s WHERE id = %s AND user_id = %s",
                    (title, content, note_id, user_id))
        conn.commit()
        cur.close()
        conn.close()
        flash("Note updated successfully.", "success")
        return redirect('/viewall')

    # If GET -> render update form with existing note data
    cur.close()
    conn.close()
    return render_template('updatenote.html', note=note)


@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    # This route expects a POST request (safer than GET for delete)
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    # Delete only if the note belongs to the current user
    cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Note deleted.", "info")
    return redirect('/viewall')


def send_reset_email(to_email, reset_link):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'yasajagan@gmail.com'  # Replace with your email
    sender_password = 'okpg iczw hmir gnpn'  # Replace with your app password
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = 'Password Reset Request'

    body = f'Click the following link to reset your password: {reset_link}'
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, to_email, text)
        server.quit()
    except Exception as e:
        print(f'Failed to send email: {e}')


if __name__ == '__main__':
    # debug=True for development only
    app.run(debug=True)
