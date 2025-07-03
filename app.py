from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from functools import wraps
import hashlib
import logging
import os

app = Flask(__name__)
app.secret_key = 'super_secret_1234567890!@#$%^&*()_LIBRARY_APP'  # Set secret key immediately after app creation

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_db_connection():
    conn = sqlite3.connect('library.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create library_books table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS library_books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            department TEXT NOT NULL,
            purchase_date TEXT NOT NULL,
            price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create issued_books table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS issued_books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL,
            borrower_name TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            return_date TEXT,
            FOREIGN KEY (book_id) REFERENCES library_books (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def add_role_column_if_not_exists():
    conn = get_db_connection()
    cursor = conn.execute("PRAGMA table_info(users)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'role' not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        conn.commit()
    conn.close()

def add_missing_columns():
    conn = get_db_connection()
    # Add phone and email to users if not exist
    cursor = conn.execute("PRAGMA table_info(users)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'phone' not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if 'email' not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    # Add phone to issued_books if not exist
    cursor = conn.execute("PRAGMA table_info(issued_books)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'phone' not in columns:
        conn.execute("ALTER TABLE issued_books ADD COLUMN phone TEXT")
    conn.commit()
    conn.close()

# Initialize the database when the app starts
init_db()
add_role_column_if_not_exists()
add_missing_columns()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form.get('email')
        phone = request.form.get('phone')
        role = 'user'  # Force role to user for all signups
        if password != confirm_password:
            flash('Passwords do not match! Please try again.', 'danger')
            return redirect(url_for('login'))
        hashed_password = hash_password(password)
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password, role, phone, email) VALUES (?, ?, ?, ?, ?)',
                        (username, hashed_password, role, phone, email))
            conn.commit()
            conn.close()
            flash('New user created', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Username already exists! Please choose a different username.', 'danger')
            return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        print(f"DEBUG LOGIN: username={username}, role={role}")
        hashed_password = hash_password(password)
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            print(f"DEBUG LOGIN: user found, db_role={user['role']}")
            if user['password'] == hashed_password:
                print("DEBUG LOGIN: password matches")
                if user['role'] == role:
                    print("DEBUG LOGIN: role matches, login success")
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user['role']
                    if role == 'admin':
                        flash('Successfully logged in as Admin!', 'success')
                    else:
                        flash('Successfully logged in as User!', 'success')
                    return redirect(url_for('index'))
                else:
                    print("DEBUG LOGIN: role mismatch")
                    flash('Wrong details', 'danger')
                    return redirect(url_for('login'))
            else:
                print("DEBUG LOGIN: password mismatch")
                flash('Wrong details', 'danger')
                return redirect(url_for('login'))
        else:
            print("DEBUG LOGIN: user not found")
            flash('Wrong details', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    print('DEBUG SESSION:', dict(session))
    return render_template('index.html')

@app.route('/add-book', methods=['GET', 'POST'])
@login_required
def add_book():
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            title = request.form['title']
            author = request.form['author']
            department = request.form['department']
            purchase_date = request.form['purchase_date']
            price = float(request.form['price'])
            
            logger.debug(f"Adding book: {title} by {author}")
            
            conn = get_db_connection()
            cursor = conn.execute('''
                INSERT INTO library_books (title, author, department, purchase_date, price)
                VALUES (?, ?, ?, ?, ?)
            ''', (title, author, department, purchase_date, price))
            conn.commit()
            book_id = cursor.lastrowid
            conn.close()
            
            logger.debug(f"Book added successfully with ID: {book_id}")
            flash('Book added successfully!', 'success')
            return redirect(url_for('view_books'))
            
        except Exception as e:
            logger.error(f"Error adding book: {str(e)}")
            flash(f'Error adding book: {str(e)}', 'danger')
            return redirect(url_for('add_book'))
            
    return render_template('add_book.html')

@app.route('/view-books')
@login_required
def view_books():
    try:
        print('DEBUG: /view-books route called')
        conn = get_db_connection()
        books = conn.execute('SELECT * FROM library_books ORDER BY id DESC').fetchall()
        print(f'DEBUG: Retrieved {len(books)} books from DB')
        # For each book, check if it is currently issued
        books_with_status = []
        for book in books:
            issued = conn.execute('''
                SELECT borrower_name FROM issued_books
                WHERE book_id = ? AND return_date IS NULL
            ''', (book['id'],)).fetchone()
            if issued:
                status = f"Issued to {issued['borrower_name']}"
            else:
                status = "Available"
            books_with_status.append({**dict(book), 'status': status})
        conn.close()
        print(f'DEBUG: Passing {len(books_with_status)} books to template')
        return render_template('view_books.html', books=books_with_status)
    except Exception as e:
        print(f'ERROR in /view-books: {e}')
        flash('Error retrieving books', 'danger')
        return redirect(url_for('index'))

@app.route('/delete-book/<int:book_id>')
@login_required
def delete_book(book_id):
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM library_books WHERE id = ?', (book_id,))
        conn.commit()
        conn.close()
        logger.debug(f"Book {book_id} deleted successfully")
        flash('Book deleted successfully!', 'success')
    except Exception as e:
        logger.error(f"Error deleting book {book_id}: {str(e)}")
        flash('Error deleting book', 'danger')
    return redirect(url_for('view_books'))

@app.route('/issue-book', methods=['GET', 'POST'])
@login_required
def issue_book():
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    book_title = request.args.get('book_title')
    username = request.args.get('username')
    if request.method == 'POST':
        try:
            book_id = request.form['book_id']
            borrower_name = request.form['borrower_name']
            phone = request.form['phone']
            issue_date = request.form['issue_date']
            request_id = request.form.get('request_id')
            logger.debug(f"Issuing book {book_id} to {borrower_name} ({phone})")
            conn = get_db_connection()
            # Check if book is already issued
            issued = conn.execute('''
                SELECT * FROM issued_books 
                WHERE book_id = ? AND return_date IS NULL
            ''', (book_id,)).fetchone()
            if issued:
                flash('This book is already issued to someone else', 'danger')
                return redirect(url_for('issue_book'))
            # Issue the book
            conn.execute('''
                INSERT INTO issued_books (book_id, borrower_name, phone, issue_date)
                VALUES (?, ?, ?, ?)
            ''', (book_id, borrower_name, phone, issue_date))
            # If this is from a book request, update its status
            if request_id:
                conn.execute('UPDATE book_requests SET status = ? WHERE id = ?', ('processed', request_id))
            conn.commit()
            conn.close()
            logger.debug(f"Book {book_id} issued successfully to {borrower_name} ({phone})")
            flash('Book issued successfully!', 'success')
            return redirect(url_for('view_books'))
        except Exception as e:
            logger.error(f"Error issuing book: {str(e)}")
            flash(f'Error issuing book: {str(e)}', 'danger')
            return redirect(url_for('issue_book'))
    # GET request - show the form
    try:
        conn = get_db_connection()
        # Get all books that are not currently issued
        available_books = conn.execute('''
            SELECT lb.* FROM library_books lb
            LEFT JOIN issued_books ib ON lb.id = ib.book_id AND ib.return_date IS NULL
            WHERE ib.id IS NULL
            ORDER BY lb.title
        ''').fetchall()
        conn.close()
        return render_template('issue_book.html', available_books=available_books, book_title=book_title, username=username)
    except Exception as e:
        logger.error(f"Error retrieving available books: {str(e)}")
        flash('Error retrieving available books', 'danger')
        return redirect(url_for('view_books'))

@app.route('/return-book', methods=['GET', 'POST'])
@login_required
def return_book():
    if request.method == 'POST':
        try:
            issue_id = request.form['issue_id']
            return_date = request.form['return_date']
            phone = request.form['phone']
            conn = get_db_connection()
            conn.execute("UPDATE issued_books SET return_date = ?, phone = ? WHERE id = ?", (return_date, phone, issue_id))
            conn.commit()
            conn.close()
            flash('Book returned successfully!', 'success')
            return redirect(url_for('view_books'))
        except Exception as e:
            flash(f'Error returning book: {e}', 'danger')
            return redirect(url_for('return_book'))
    try:
        conn = get_db_connection()
        if session.get('role') == 'admin':
            issued_books = conn.execute('''
                SELECT ib.id, lb.title, ib.borrower_name, ib.issue_date
                FROM issued_books ib
                JOIN library_books lb ON ib.book_id = lb.id
                WHERE ib.return_date IS NULL
                ORDER BY ib.issue_date DESC
            ''').fetchall()
        else:
            issued_books = conn.execute('''
                SELECT ib.id, lb.title, ib.borrower_name, ib.issue_date
                FROM issued_books ib
                JOIN library_books lb ON ib.book_id = lb.id
                WHERE ib.return_date IS NULL AND ib.borrower_name = ?
                ORDER BY ib.issue_date DESC
            ''', (session['username'],)).fetchall()
        conn.close()
        return render_template('return_book.html', issued_books=issued_books)
    except Exception as e:
        flash('Error loading issued books', 'danger')
        return redirect(url_for('view_books'))

@app.route('/issued-books')
@login_required
def issued_books():
    try:
        conn = get_db_connection()
        if session.get('role') == 'admin':
            issued = conn.execute('''
                SELECT ib.id, lb.title, ib.borrower_name, ib.phone, ib.issue_date, ib.return_date
                FROM issued_books ib
                JOIN library_books lb ON ib.book_id = lb.id
                ORDER BY ib.issue_date DESC
            ''').fetchall()
        else:
            issued = conn.execute('''
                SELECT ib.id, lb.title, ib.borrower_name, ib.phone, ib.issue_date, ib.return_date
                FROM issued_books ib
                JOIN library_books lb ON ib.book_id = lb.id
                WHERE ib.borrower_name = ?
                ORDER BY ib.issue_date DESC
            ''', (session['username'],)).fetchall()
        conn.close()
        return render_template('issued_books.html', issued_books=issued)
    except Exception as e:
        flash('Error loading issued books', 'danger')
        return redirect(url_for('view_books'))

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '')
    results = []
    if query:
        conn = get_db_connection()
        results = conn.execute(
            "SELECT * FROM library_books WHERE title LIKE ? OR author LIKE ?",
            ('%' + query + '%', '%' + query + '%')
        ).fetchall()
        conn.close()
    return render_template('search.html', results=results)

@app.route('/test-view')
def test_view():
    return "<h1>Test View Works</h1>"

@app.route('/view-books-demo')
def view_books_demo():
    demo_books = [
        {'id': 1, 'title': 'Book A', 'author': 'Author A', 'department': 'Dept A', 'purchase_date': '2024-01-01', 'price': 100, 'status': 'Available'},
        {'id': 2, 'title': 'Book B', 'author': 'Author B', 'department': 'Dept B', 'purchase_date': '2024-02-01', 'price': 200, 'status': 'Issued to John'},
    ]
    return render_template('view_books.html', books=demo_books)

@app.route('/history')
@login_required
def history():
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        # Books added
        added_books = conn.execute('''
            SELECT id, title, author, department, purchase_date, price, created_at
            FROM library_books
            ORDER BY created_at DESC
        ''').fetchall()
        # Books issued
        issued_books = conn.execute('''
            SELECT ib.id, lb.title, ib.borrower_name, ib.issue_date
            FROM issued_books ib
            JOIN library_books lb ON ib.book_id = lb.id
            ORDER BY ib.issue_date DESC
        ''').fetchall()
        # Books returned
        returned_books = conn.execute('''
            SELECT ib.id, lb.title, ib.borrower_name, ib.issue_date, ib.return_date
            FROM issued_books ib
            JOIN library_books lb ON ib.book_id = lb.id
            WHERE ib.return_date IS NOT NULL
            ORDER BY ib.return_date DESC
        ''').fetchall()
        conn.close()
        return render_template('history.html', added_books=added_books, issued_books=issued_books, returned_books=returned_books)
    except Exception as e:
        flash('Error loading history', 'danger')
        return redirect(url_for('index'))

@app.route('/user-history')
@login_required
def user_history():
    if session.get('role') != 'user':
        flash('Access denied: Users only.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        # Books issued to this user
        issued_books = conn.execute('''
            SELECT ib.id, lb.title, ib.issue_date
            FROM issued_books ib
            JOIN library_books lb ON ib.book_id = lb.id
            WHERE ib.borrower_name = ? AND ib.return_date IS NULL
            ORDER BY ib.issue_date DESC
        ''', (session['username'],)).fetchall()
        # Books returned by this user
        returned_books = conn.execute('''
            SELECT ib.id, lb.title, ib.issue_date, ib.return_date
            FROM issued_books ib
            JOIN library_books lb ON ib.book_id = lb.id
            WHERE ib.borrower_name = ? AND ib.return_date IS NOT NULL
            ORDER BY ib.return_date DESC
        ''', (session['username'],)).fetchall()
        conn.close()
        return render_template('user_history.html', issued_books=issued_books, returned_books=returned_books)
    except Exception as e:
        flash('Error loading user history', 'danger')
        return redirect(url_for('index'))

@app.route('/test-flash')
def test_flash():
    flash('This is a test flash message!', 'info')
    return redirect(url_for('login'))

@app.route('/minimal-flash')
def minimal_flash():
    from flask import render_template_string
    flash('This is a minimal test flash message!', 'info')
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head><title>Minimal Flash Test</title></head>
        <body>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div style="max-width: 500px; margin: 30px auto 0 auto;">
                        {% for category, message in messages %}
                            <div style="border:2px solid #333; background:#eef; padding:10px; margin:10px 0;">{{ message }}</div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}
            <h2>If you see this, flash works!</h2>
        </body>
        </html>
    ''')

@app.route('/test-login-flash')
def test_login_flash():
    template_path = os.path.abspath(os.path.join(app.root_path, 'templates', 'login.html'))
    print('DEBUG: Rendering template at', template_path)
    flash('This is a direct login page flash test!', 'info')
    return render_template('login.html')

@app.route('/edit-book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('view_books'))
    conn = get_db_connection()
    book = conn.execute('SELECT * FROM library_books WHERE id = ?', (book_id,)).fetchone()
    if not book:
        conn.close()
        flash('Book not found.', 'danger')
        return redirect(url_for('view_books'))
    if request.method == 'POST':
        try:
            title = request.form['title']
            author = request.form['author']
            department = request.form['department']
            purchase_date = request.form['purchase_date']
            price = float(request.form['price'])
            conn.execute('''
                UPDATE library_books
                SET title = ?, author = ?, department = ?, purchase_date = ?, price = ?
                WHERE id = ?
            ''', (title, author, department, purchase_date, price, book_id))
            conn.commit()
            conn.close()
            flash('Book updated successfully!', 'success')
            return redirect(url_for('view_books'))
        except Exception as e:
            conn.close()
            flash(f'Error updating book: {str(e)}', 'danger')
            return redirect(url_for('edit_book', book_id=book_id))
    conn.close()
    return render_template('edit_book.html', book=book)

@app.route('/users')
@login_required
def users():
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT id, username, role, phone, email FROM users ORDER BY id DESC').fetchall()
        conn.close()
        return render_template('users.html', users=users)
    except Exception as e:
        flash('Error loading users', 'danger')
        return redirect(url_for('index'))

@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('users'))
    if request.method == 'POST':
        username = request.form['username']
        phone = request.form['phone']
        email = request.form['email']
        role = request.form['role']
        try:
            conn.execute('UPDATE users SET username = ?, phone = ?, email = ?, role = ? WHERE id = ?',
                         (username, phone, email, role, user_id))
            conn.commit()
            conn.close()
            flash('User updated successfully!', 'success')
            return redirect(url_for('users'))
        except Exception as e:
            conn.close()
            flash(f'Error updating user: {str(e)}', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    return redirect(url_for('users'))

# Add book_requests table if not exists
def add_book_requests_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS book_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            author TEXT,
            status TEXT DEFAULT 'pending'
        )
    ''')
    conn.commit()
    conn.close()

add_book_requests_table()

@app.route('/request-book', methods=['GET', 'POST'])
@login_required
def request_book():
    if session.get('role') != 'user':
        flash('Only users can request books.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        book_id = request.form['book_id']
        username = session['username']
        try:
            conn = get_db_connection()
            # Get book details from the selected book_id
            book = conn.execute('SELECT title, author FROM library_books WHERE id = ?', (book_id,)).fetchone()
            if not book:
                flash('Book not found.', 'danger')
                return redirect(url_for('request_book'))
            conn.execute('INSERT INTO book_requests (username, title, author) VALUES (?, ?, ?)',
                         (username, book['title'], book['author']))
            conn.commit()
            conn.close()
            flash('Book request submitted!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error submitting request: {str(e)}', 'danger')
            return redirect(url_for('request_book'))
    # GET request - show form with available books
    try:
        conn = get_db_connection()
        # Get all books that are not currently issued
        available_books = conn.execute('''
            SELECT lb.* FROM library_books lb
            LEFT JOIN issued_books ib ON lb.id = ib.book_id AND ib.return_date IS NULL
            WHERE ib.id IS NULL
            ORDER BY lb.title
        ''').fetchall()
        conn.close()
        return render_template('request_book.html', available_books=available_books)
    except Exception as e:
        flash('Error loading available books', 'danger')
        return redirect(url_for('index'))

@app.route('/book-requests')
@login_required
def book_requests():
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('index'))
    conn = get_db_connection()
    requests = conn.execute('SELECT * FROM book_requests ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('book_requests.html', requests=requests)

if __name__ == '__main__':
    app.run(debug=True, port=5050)
