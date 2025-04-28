# BugBrewer

BugBrewer is a web-based security scanning tool that helps identify vulnerabilities in web applications and networks. It provides a user-friendly interface for running various security scans and managing assets.

Can be used with a list of domains from https://github.com/arkadiyt/bounty-targets-data/blob/main/data/domains.txt

## Features

- Asset Management (Domains, IPs, Subdomains)
- Multiple Scan Modules
  - Nmap Scanner
  - FFuf Scanner
  - Subdomain Recon
  - Port Scanner
- Scan Scheduling and History
- Finding Management
- Favorites System
- Ignored Assets Management
- Tag System
- API Support

## Requirements

- Python 3.10+
- Redis
- Nmap
- Feroxbuster
- FFuf
- Nuclei
- Subfinder
- Chrome/Chromium
- Playwright

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/bugbrewer.git
cd bugbrewer
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Playwright browsers:
```bash
playwright install chromium
```

5. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your settings
```

6. Run migrations:
```bash
python manage.py migrate
```

7. Start Redis:
```bash
redis-server
```

8. Start Celery worker:
```bash
celery -A bugbrewer worker --loglevel=info
```

9. Run the development server:
```bash
python manage.py runserver
```

## Docker Installation

1. Build and start the containers:
```bash
docker-compose up --build
```

2. Access the application at `http://localhost:8000`

## Usage

1. Add assets (domains or IPs) through the web interface
2. Configure scan modules in the Modules section
3. Run scans on assets or subdomains
4. Review findings and manage them through the interface

## API Documentation

The application provides a REST API for programmatic access. API documentation is available at `/api/` when running the server.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

Please report security vulnerabilities to [your-email@example.com]

## Acknowledgments

- Django
- Celery
- Redis
- Playwright
- Various security tools integrated into the platform 