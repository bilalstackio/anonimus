# Anonimus - Anonymous Q&A Tool

A simple, secure web application for anonymous question submission in live classes, built with Flask.

## Features

### For Students
- Submit questions anonymously
- View all questions and comments
- Add comments to any question anonymously

### For Teachers (Admin)
- All student features plus:
- Login with secure password authentication
- Mark questions as "done" with visual feedback
- Delete inappropriate comments
- Comments are marked with "Teacher" badge
- Admin controls visible only when logged in

### Security Features
- CSRF protection on all forms
- XSS prevention with input sanitization
- Secure password hashing
- Session-based authentication
- SQL injection protection with parameterized queries

## Project Structure

```
anonimus/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env.example          # Environment configuration template
├── .env                  # Your environment variables (create this)
├── anonimus.db           # SQLite database (auto-created)
├── templates/
│   ├── base.html         # Base template with styles
│   ├── index.html        # Main page template
│   └── admin_login.html  # Admin login template
└── static/              # Static files (if needed)
```

## Installation & Setup

1. **Clone or download the project files**

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   ```bash
   # Copy the example file
   cp .env.example .env
   
   # Generate a secure secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Generate admin password hash (replace 'your_password' with your desired password)
   python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))"
   ```

5. **Update .env file** with your generated values:
   ```
   SECRET_KEY=your_generated_secret_key
   ADMIN_PASSWORD_HASH=your_generated_password_hash
   ```

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Access the application**:
   - Main page: http://localhost:5000
   - Admin login: http://localhost:5000/admin/login

## Usage

### For Students
1. Visit the main page
2. Submit questions anonymously using the form
3. View all questions and their comments
4. Add comments to any question

### For Teachers
1. Go to `/admin/login` or click the login link
2. Enter your admin password
3. Once logged in, you'll see additional controls:
   - "Mark as Done" buttons on questions
   - "Delete" buttons on comments
   - Your comments will show a "Teacher" badge

### Admin Features
- **Mark Questions as Done**: Click the "Mark Done" button to strike through completed questions
- **Delete Comments**: Remove inappropriate or irrelevant comments
- **Teacher Badge**: Your comments are automatically marked with a "Teacher" badge
- **Session Management**: Admin status persists until logout or session expiration

## Security Notes

- Never commit your `.env` file to version control
- Use strong, unique passwords for admin access
- The app uses CSRF tokens to prevent cross-site request forgery
- All user input is sanitized to prevent XSS attacks
- Passwords are hashed using Werkzeug's secure methods

## Customization

### Changing the Admin Password
1. Generate a new hash: `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('new_password'))"`
2. Update the `ADMIN_PASSWORD_HASH` in your `.env` file
3. Restart the application

### Styling
- All CSS is included in `templates/base.html`
- Modify the `<style>` section to customize appearance
- The design is responsive and mobile-friendly

### Database
- Uses SQLite by default (file: `anonimus.db`)
- Database is automatically created on first run
- To reset: delete `anonimus.db` and restart the app

## Production Deployment

For production use:
1. Set `app.run(debug=False)` in `app.py`
2. Use a production WSGI server (e.g., Gunicorn)
3. Set up proper environment variables
4. Consider using a more robust database (PostgreSQL, MySQL)
5. Enable HTTPS
6. Set up proper logging

## License

This project is open source and available under the MIT License.
