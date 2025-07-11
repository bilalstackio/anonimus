import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import TextAreaField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup
import bleach
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['ADMIN_PASSWORD_HASH'] = os.getenv('ADMIN_PASSWORD_HASH', generate_password_hash('admin123'))

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Database setup
DATABASE = 'anonimus.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_done BOOLEAN DEFAULT FALSE
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (question_id) REFERENCES questions (id)
            )
        ''')
        conn.commit()

# Forms
class QuestionForm(FlaskForm):
    content = TextAreaField('Question', validators=[DataRequired(), Length(min=10, max=500)], 
                           render_kw={"placeholder": "Ask your question anonymously..."})
    submit = SubmitField('Submit Question')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=3, max=300)], 
                           render_kw={"placeholder": "Add a comment..."})
    submit = SubmitField('Add Comment')

class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks"""
    allowed_tags = ['p', 'br', 'strong', 'em', 'u']
    return bleach.clean(text, tags=allowed_tags, strip=True)

def is_admin():
    """Check if current user is admin"""
    return session.get('is_admin', False)

@app.route('/')
def index():
    question_form = QuestionForm()
    comment_form = CommentForm()
    
    with get_db() as conn:
        questions = conn.execute('''
            SELECT id, content, created_at, is_done 
            FROM questions 
            ORDER BY created_at DESC
        ''').fetchall()
        
        # Get comments for each question
        question_data = []
        for question in questions:
            comments = conn.execute('''
                SELECT content, is_admin, created_at 
                FROM comments 
                WHERE question_id = ? 
                ORDER BY created_at ASC
            ''', (question['id'],)).fetchall()
            
            question_data.append({
                'question': question,
                'comments': comments
            })
    
    return render_template('index.html', 
                         question_data=question_data,
                         question_form=question_form,
                         comment_form=comment_form,
                         is_admin=is_admin())

@app.route('/submit_question', methods=['POST'])
def submit_question():
    form = QuestionForm()
    if form.validate_on_submit():
        content = sanitize_input(form.content.data)
        
        with get_db() as conn:
            conn.execute('INSERT INTO questions (content) VALUES (?)', (content,))
            conn.commit()
        
        flash('Question submitted successfully!', 'success')
    else:
        flash('Please enter a valid question (10-500 characters).', 'error')
    
    return redirect(url_for('index'))

@app.route('/add_comment/<int:question_id>', methods=['POST'])
def add_comment(question_id):
    form = CommentForm()
    if form.validate_on_submit():
        content = sanitize_input(form.content.data)
        is_admin_comment = is_admin()
        
        with get_db() as conn:
            conn.execute('''
                INSERT INTO comments (question_id, content, is_admin) 
                VALUES (?, ?, ?)
            ''', (question_id, content, is_admin_comment))
            conn.commit()
        
        flash('Comment added successfully!', 'success')
    else:
        flash('Please enter a valid comment (3-300 characters).', 'error')
    
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not is_admin():
        return redirect(url_for('admin_login'))
    
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_admin():
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        if check_password_hash(app.config['ADMIN_PASSWORD_HASH'], password):
            session['is_admin'] = True
            flash('Successfully logged in as admin!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid password!', 'error')
    
    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Successfully logged out!', 'info')
    return redirect(url_for('index'))

@app.route('/admin/mark_done/<int:question_id>', methods=['POST'])
def mark_question_done(question_id):
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    with get_db() as conn:
        conn.execute('UPDATE questions SET is_done = NOT is_done WHERE id = ?', (question_id,))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    with get_db() as conn:
        conn.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
        conn.commit()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.template_filter('datetime')
def datetime_filter(value):
    """Format datetime for display"""
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        dt = value
    return dt.strftime('%Y-%m-%d %H:%M')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)