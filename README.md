# FastAPI Calculator Application with User Profiles

A production-ready FastAPI application featuring JWT-based authentication, calculation management with full CRUD operations, user profile management with password change functionality, PostgreSQL database integration, and automated CI/CD deployment pipeline.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [CI/CD Pipeline](#cicd-pipeline)
- [Docker Deployment](#docker-deployment)
- [Project Structure](#project-structure)

## Overview

This application demonstrates modern web development practices with:
- JWT-based authentication system
- User profile management with secure password changes
- Full BREAD (Browse, Read, Edit, Add, Delete) operations for calculations
- Comprehensive testing (unit, integration, and E2E with Playwright)
- Automated CI/CD pipeline with security scanning
- Docker containerization for easy deployment

## Features

### Authentication & Security
- JWT token-based authentication (access and refresh tokens)
- Secure password hashing with bcrypt
- Password strength validation
- Token-based authorization for protected routes

### User Profile Management
- View complete user profile with statistics
- Update username, email, first name, and last name
- Secure password change with current password verification
- Profile statistics (total calculations, member since date)
- Duplicate username/email prevention

### Calculation Operations
- Four arithmetic operations (addition, subtraction, multiplication, division)
- User-specific calculation history
- Full CRUD operations on calculations
- Input validation and error handling

### Front-End Interface
- Responsive design with Tailwind CSS
- Login and registration pages with client-side validation
- User dashboard with calculation management
- Profile page with update and password change forms
- Real-time error and success feedback

## Technology Stack

- **Framework**: FastAPI 0.115.8
- **Database**: PostgreSQL 17
- **ORM**: SQLAlchemy 2.0.38
- **Authentication**: python-jose (JWT), passlib (bcrypt)
- **Validation**: Pydantic 2.10.6
- **Templates**: Jinja2 3.1.5
- **Testing**: pytest 8.3.4, pytest-cov 6.0.0, Playwright 1.50.0
- **Web Server**: Uvicorn 0.34.0
- **Containerization**: Docker with multi-platform builds
- **CI/CD**: GitHub Actions
- **Security**: Trivy vulnerability scanner

## Installation

### Prerequisites

- Python 3.10 or higher
- PostgreSQL 13 or higher (or Docker)
- Docker and Docker Compose (recommended)
- Git

### Local Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Playwright browsers (for E2E tests):
```bash
playwright install
```

5. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Running the Application

### Using Docker Compose (Recommended)

```bash
docker-compose up
```

This starts:
- FastAPI application on `http://localhost:8000`
- PostgreSQL database on port 5432
- pgAdmin on `http://localhost:5050`

### Local Development

1. Start PostgreSQL (if not using Docker)

2. Initialize the database:
```bash
python -m app.database_init
```

3. Run the application:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

4. Access the application:
- Home Page: `http://localhost:8000/`
- API Documentation: `http://localhost:8000/docs`
- Login: `http://localhost:8000/login`
- Register: `http://localhost:8000/register`
- Dashboard: `http://localhost:8000/dashboard`
- Profile: `http://localhost:8000/profile`

## API Endpoints

### Authentication

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and receive JWT tokens
- `POST /auth/token` - OAuth2 compatible token endpoint

### Profile Management

- `GET /profile/me` - Get current user profile
- `PUT /profile/me` - Update user profile
- `POST /profile/change-password` - Change password

### Calculations

- `POST /calculations` - Create a new calculation
- `GET /calculations` - List user's calculations
- `GET /calculations/{id}` - Get specific calculation
- `PUT /calculations/{id}` - Update a calculation
- `DELETE /calculations/{id}` - Delete a calculation

### Health Check

- `GET /health` - Application health status

For detailed API documentation, visit `/docs` when the application is running.

## Testing

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# E2E tests
pytest tests/e2e/ -v

# Profile feature tests
pytest tests/unit/test_profile_logic.py tests/integration/test_profile_routes.py tests/e2e/test_profile_e2e.py -v
```

### Run with Coverage

```bash
pytest --cov=app --cov-report=html
```

View coverage report:
```bash
open htmlcov/index.html  # macOS
start htmlcov/index.html  # Windows
```

### Test Coverage

The application includes:
- **Unit Tests**: Schema validation, business logic
- **Integration Tests**: Database operations, route handlers
- **E2E Tests**: Complete user workflows with Playwright
  - Positive tests (successful operations)
  - Negative tests (error handling, validation)

## CI/CD Pipeline

### GitHub Actions Workflow

The pipeline consists of three jobs:

#### 1. Test Job
- Sets up PostgreSQL service
- Installs dependencies
- Runs unit, integration, and E2E tests
- Generates coverage reports

#### 2. Security Job
- Builds Docker image
- Runs Trivy vulnerability scanner
- Checks for CRITICAL and HIGH vulnerabilities

#### 3. Deploy Job
- Only runs on main branch
- Requires test and security jobs to pass
- Builds multi-platform Docker image
- Pushes to Docker Hub with tags (latest and commit SHA)

### Setting Up CI/CD

1. Configure GitHub Secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Your Docker Hub access token

2. Create production environment in GitHub repository settings

3. Update Docker Hub repository name in `.github/workflows/python-app.yml`

## Docker Deployment

### Build Docker Image

```bash
docker build -t your-username/calculator-app:latest .
```

### Run Docker Container

```bash
docker run -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  -e JWT_SECRET_KEY=your-secret-key \
  -e JWT_REFRESH_SECRET_KEY=your-refresh-secret \
  your-username/calculator-app:latest
```

### Docker Compose

See `docker-compose.yml` for complete setup including PostgreSQL and pgAdmin.

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── python-app.yml          # CI/CD pipeline
├── app/
│   ├── auth/
│   │   ├── dependencies.py         # Auth dependencies
│   │   ├── jwt.py                  # JWT handling
│   │   └── redis.py                # Token blacklisting
│   ├── core/
│   │   └── config.py               # App configuration
│   ├── models/
│   │   ├── calculation.py          # Calculation models
│   │   └── user.py                 # User model
│   ├── routes/
│   │   └── profile.py              # Profile routes
│   ├── schemas/
│   │   ├── calculation.py          # Calculation schemas
│   │   ├── profile.py              # Profile schemas
│   │   ├── token.py                # Token schemas
│   │   └── user.py                 # User schemas
│   ├── database.py                 # Database config
│   ├── database_init.py            # DB initialization
│   └── main.py                     # Application entry
├── static/
│   ├── css/
│   │   └── style.css               # Custom styles
│   └── js/
│       └── script.js               # Client scripts
├── templates/
│   ├── dashboard.html              # User dashboard
│   ├── index.html                  # Home page
│   ├── layout.html                 # Base template
│   ├── login.html                  # Login page
│   ├── profile.html                # Profile page
│   └── register.html               # Registration page
├── tests/
│   ├── e2e/
│   │   ├── test_fastapi_calculator.py
│   │   └── test_profile_e2e.py
│   ├── integration/
│   │   ├── test_profile_routes.py
│   │   └── ...
│   ├── unit/
│   │   ├── test_profile_logic.py
│   │   └── ...
│   └── conftest.py                 # Test fixtures
├── .env.example                    # Environment template
├── .gitignore                      # Git ignore rules
├── docker-compose.yml              # Docker services
├── Dockerfile                      # Docker image
├── init-db.sh                      # DB init script
├── pytest.ini                      # Pytest config
├── requirements.txt                # Dependencies
└── README.md                       # This file
```

## Security Considerations

- JWT tokens with configurable expiration
- Bcrypt password hashing with configurable rounds
- Password strength validation
- SQL injection prevention via SQLAlchemy ORM
- CORS configuration
- Non-root user in Docker container
- Input validation with Pydantic
- Token-based authorization

## Development Guidelines

### Adding New Features

1. Create necessary models in `app/models/`
2. Define Pydantic schemas in `app/schemas/`
3. Implement routes in `app/routes/` or `app/main.py`
4. Write unit tests in `tests/unit/`
5. Write integration tests in `tests/integration/`
6. Write E2E tests in `tests/e2e/`
7. Update documentation

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for public functions
- Keep functions focused and small
- Use meaningful variable names

## Troubleshooting

### Common Issues

**Database Connection Error:**
- Verify PostgreSQL is running
- Check DATABASE_URL in environment
- Ensure database exists

**Authentication Errors:**
- Check JWT_SECRET_KEY is set
- Verify token hasn't expired
- Ensure proper Authorization header format

**Tests Failing:**
- Check PostgreSQL service is running
- Verify test database exists
- Review test configuration in pytest.ini