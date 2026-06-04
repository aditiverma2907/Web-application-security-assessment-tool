<<<<<<< HEAD
# Web Application Security Assessment Tool

A full-stack educational cybersecurity web application built with Flask, HTML5, CSS3, Bootstrap 5, and JavaScript. The project demonstrates a basic application security assessment workflow for authorized and demo websites only.

## Disclaimer

This project is developed strictly for educational purposes and authorized security testing only.

For Educational and Authorized Security Testing Purposes Only.

## Features

- Security header analysis
- Common open port detection
- Safe reflection-based XSS awareness check
- Basic SQL injection pattern testing
- Risk classification engine
- Professional scan report generation
- Scan history storage using SQLite
- Responsive dark cybersecurity UI
- Database-ready modular structure with placeholders

## Technologies Used

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript

### Backend
- Python
- Flask
- requests
- BeautifulSoup4
- socket
- urllib
- Jinja2

## Project Structure

```text
project/
├── app.py
├── scanner.py
├── db.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── about.html
│   ├── features.html
│   ├── history.html
│   └── results.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── script.js
```

## Installation

1. Create and activate a Python virtual environment if desired.
2. Install the dependencies:

```bash
pip install flask requests beautifulsoup4
```

3. Run the application:

```bash
python app.py
```

4. Open the local server in your browser, usually:

```text
http://127.0.0.1:5000
```

## Usage

1. Enter an authorized demo URL on the home page.
2. Start the scan.
3. Review the dashboard for header findings, open ports, XSS reflection checks, SQL injection indicators, risk levels, and recommendations.

Example authorized demo target:

```text
http://testphp.vulnweb.com
```

## Educational Scope

The scanner demonstrates common application security assessment ideas used in internship learning and viva presentations:

- Why security headers matter
- Why port exposure matters
- Why reflected input handling matters
- Why parameterized database access matters
- How to summarize findings into a risk view

## Database Placeholder

Database integration is intentionally modular and not hard-coded. The `db.py` file contains placeholders for future storage of:

- Scan history
- Authentication
- Saved reports

The scan history page uses a lightweight SQLite database stored in the project folder so completed assessments can be reviewed later.

## Ethical Notice

Only use this tool on systems you own or are explicitly authorized to test.

For Educational and Authorized Security Testing Purposes Only.
=======
# Web-application-security-assessment-tool
>>>>>>> e394b5f14eeddd3e45a604aca2fd2e3fddd3e9ab
