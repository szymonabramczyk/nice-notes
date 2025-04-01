# Nice Notes

This project is a secure note-taking web application built with **Flask** and **SQLAlchemy**, featuring end-to-end encryption, user authentication, and role-based access control. The application is containerized using **Docker** and serves requests through **Nginx** as a reverse proxy.

## Technologies Used
- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: Jinja2, HTML, CSS, Bootstrap 5
- **Security**: Cryptography, JWT-based authentication, bcrypt password hashing
- **Deployment**: Docker, Docker Compose, Gunicorn, Nginx

## Features
- **User Authentication**: Secure login and session management with Flask-Login.
- **End-to-End Encryption**: Users can encrypt notes with a secret key.
- **Signature Verification**: Ensures note integrity using digital signatures.
- **Role-Based Access Control**: Private, shared, and public note visibility.
- **Secure Storage**: Notes are stored in an encrypted format.
- **Dockerized Deployment**: Uses Docker Compose for easy deployment.
- **Reverse Proxy with Nginx**: Secures and optimizes traffic handling.

## Security Features
- **Input Validation**: All user inputs are validated with a negative approach.
- **Brute-force Protection**: Login attempts are limited and delayed.
- **Minimal Error Feedback**: Prevents information leaks about authentication failures.
- **Password Hashing**: Uses bcrypt with salt and multiple hashing rounds.
- **Password Strength Control**: Ensures users create strong passwords.
- **Resource Access Management**: Controls user permissions.
- **SQL Database Support**: Uses SQLite or other SQL databases.
- **Production-Grade Web Server**: Uses Nginx instead of development servers.
- **Encrypted Connection**: HTTPS with SSL certificates.
- **User Access Verification**: Ensures proper authorization to resources.
- **Failed Login Attempt Monitoring**: Tracks and restricts excessive login attempts.
- **Cross-Site Request Forgery (CSRF) Protection**: Prevents CSRF attacks.
- **Password Recovery Mechanism**: Allows users to recover lost access securely.
- **System Monitoring**: Notifies users of new login locations.
- **Content Security Policy (CSP)**: Protects against XSS attacks.

## Installation & Setup
### Prerequisites
Ensure you have the following installed on your machine:
- Docker
- Docker Compose

### Steps to Run the Application
1. Clone the repository:
   ```sh
   git clone https://github.com/szymonabramczyk/nice-notes.git
   cd nice-notes
   ```
2. Create an `.env` file in the root directory with the necessary environment variables:
   ```sh
   SECRET_KEY=your_secret_key
   SECRET_KEY_SECRET_TOKEN=your_secret_token
   SECRET_KEY_RESET_PASSWORD_TOKEN=your_reset_token
   SECRET_KEY_ENCODE_ID=your_encode_key
   MAIL_PASSWORD=your_mail_password
   DEFAULT_MAIL_SENDER=your_mail@example.com
   ```
3. Generate a key and a certificate, and place it in the `nginx/certs` directory.
4. Build and start the Docker containers:
   ```sh
   docker-compose up --build
   ```
5. Access the application at `https://localhost`.

## Directory Structure
```
nice-notes/
│── app/
│   ├── instance/
│   ├── website/
│   │   ├── forms/          # Flask-WTF forms
│   │   ├── models/         # Database models
│   │   ├── static/         # CSS and JS files
│   │   ├── templates/      # HTML templates
│   │   ├── utils/          # Encryption and signature utilities
│   │   ├── __init__.py     
│   │   ├── auth.py         # Routes for authentication logic
│   │   ├── config.py       # App config
│   │   ├── views.py        # Routes and view logic
│   ├── Dockerfile          # Flask application Dockerfile
│   ├── main.py             # Main file used to run the app
│   ├── requirements.txt
│── nginx/
│   ├── nginx.conf          # Nginx configuration file
│   ├── certs/              # SSL certificates
│── docker-compose.yml      # Docker Compose file
│── .gitignore         
```


## License
This project is licensed under the MIT License.

## Contributors
- Szymon Abramczyk

## Contact
For questions or support, open an issue on GitHub.

