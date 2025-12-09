# FastAPI Calculator Application with User Profiles

A production-ready FastAPI application featuring JWT-based authentication, calculation management with full CRUD operations, comprehensive user profile management, PostgreSQL database integration with polymorphic models, and automated CI/CD deployment pipeline with security scanning.

## Table of Contents

- [Overview](#overview)
- [Architecture & Design Patterns](#architecture--design-patterns)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [CI/CD Pipeline](#cicd-pipeline)
- [Docker Deployment](#docker-deployment)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Performance & Scalability](#performance--scalability)
- [Development Guidelines](#development-guidelines)
- [Troubleshooting](#troubleshooting)

## Overview

This application demonstrates modern web development practices with:
- JWT-based authentication system with access and refresh tokens
- User profile management with secure password changes
- Polymorphic calculation models (Addition, Subtraction, Multiplication, Division)
- Full BREAD (Browse, Read, Edit, Add, Delete) operations for calculations
- Comprehensive testing (unit, integration, and E2E with Playwright)
- Automated CI/CD pipeline with security scanning (Trivy)
- Docker containerization for easy deployment
- PostgreSQL with cascade deletion and relationship management
- Responsive web interface with Tailwind CSS

## Architecture & Design Patterns

### Backend Architecture
- **Layered Architecture**: Separation of concerns (routes, models, schemas, services)
- **Dependency Injection**: FastAPI's built-in DI for database sessions and auth
- **Repository Pattern**: Database access through SQLAlchemy ORM
- **Factory Pattern**: Calculation model creation with polymorphism
- **Singleton Pattern**: Settings configuration with lru_cache

### Database Design
- **Polymorphic Inheritance**: Base Calculation class with specialized subclasses
  - AbstractCalculation defines shared columns and behavior
  - Calculation is the base model with `polymorphic_on="type"`
  - Addition, Subtraction, Multiplication, Division inherit and override `get_result()`
- **Cascade Deletion**: User deletion automatically removes associated calculations
  - Configured with `cascade="all, delete-orphan"` on relationships
  - Foreign key constraint with `ondelete='CASCADE'`
- **Indexing**: user_id, type, username, and email fields indexed for performance
- **Timezone-Aware**: All timestamps use UTC timezone via `DateTime(timezone=True)`
- **UUID Primary Keys**: Enhanced security and distributed system compatibility
- **Unique Constraints**: Username and email must be unique across users
- **Relationships**: User.calculations (one-to-many) and Calculation.user (many-to-one)

### Models Overview

**User Model** (`app/models/user.py`):
- Fields: id (UUID), username, email, password, first_name, last_name, is_active, is_verified, created_at, updated_at, last_login
- Methods: `register()`, `authenticate()`, `verify_password()`, `hash_password()`, `update()`
- Class methods: `create_access_token()`, `create_refresh_token()`, `verify_token()`

**Calculation Models** (`app/models/calculation.py`):
- Base fields: id (UUID), user_id, type, inputs (JSON), result, created_at, updated_at
- Factory method: `create(type, user_id, inputs)` returns appropriate subclass
- Polymorphic classes: Addition, Subtraction, Multiplication, Division
- Each implements `get_result()` with operation-specific logic

### Authentication Flow
1. User registers → Password hashed with bcrypt → User created in database
2. User logs in → Credentials verified → JWT tokens generated (access + refresh)
3. Protected endpoints → Token validated → User extracted from token
4. Token expiry → Refresh token used to obtain new access token

### API Design
- **RESTful**: Standard HTTP methods (GET, POST, PUT, DELETE)
- **Pydantic Validation**: Request/response validation with custom validators
- **Error Handling**: Consistent error responses with appropriate status codes
- **Documentation**: Auto-generated OpenAPI/Swagger documentation

## Features

### Authentication & Security
- JWT token-based authentication (access and refresh tokens)
- Secure password hashing with bcrypt (configurable rounds)
- Password strength validation (uppercase, lowercase, digit, special character)
- Token-based authorization for protected routes
- OAuth2 password flow compatibility for Swagger UI
- Token blacklisting support (Redis-ready stub implementation)
- Non-root Docker user for enhanced security
- CORS configuration
- SQL injection prevention via SQLAlchemy ORM

### User Profile Management
- View complete user profile with statistics (calculation count, member since)
- Update username, email, first name, and last name
- Secure password change with current password verification
- Duplicate username/email prevention with database constraints
- Profile statistics tracking
- Last login timestamp tracking
- Timezone-aware timestamps

### Calculation Operations
- Four polymorphic calculation types (Addition, Subtraction, Multiplication, Division)
- User-specific calculation history with cascade deletion
- Full BREAD (Browse, Read, Edit, Add, Delete) operations
- Input validation and error handling (division by zero, minimum inputs)
- Automatic result computation using polymorphic `get_result()` method
- JSON storage for calculation inputs (supports any number of operands)
- Timestamp tracking (created_at, updated_at)
- Factory method pattern for calculation instantiation
- Polymorphic identity for efficient database queries

### Front-End Interface
- Responsive design with Tailwind CSS
- Login and registration pages with client-side validation
- User dashboard with calculation management
- Profile page with update and password change forms
- Real-time error and success feedback
- Token-based session management
- "Remember me" functionality
- Dynamic calculation table with delete functionality

## Technology Stack

- **Framework**: FastAPI 0.115.8
- **Database**: PostgreSQL 17 with SQLAlchemy 2.0.38 ORM
- **Authentication**: python-jose (JWT), passlib with bcrypt
- **Validation**: Pydantic 2.10.6 with custom validators
- **Templates**: Jinja2 3.1.5
- **Testing**: pytest 8.3.4, pytest-cov 6.0.0, pytest-asyncio 0.22.0, Playwright 1.50.0
- **Web Server**: Uvicorn 0.34.0
- **Containerization**: Docker with multi-platform builds (AMD64/ARM64)
- **CI/CD**: GitHub Actions with automated testing and deployment
- **Security**: Trivy vulnerability scanner, bcrypt password hashing
- **Frontend**: Tailwind CSS, vanilla JavaScript

## Installation

### Prerequisites

- Python 3.10 or higher
- PostgreSQL 13 or higher (or Docker)
- Docker and Docker Compose (recommended)
- Git

### Local Setup

1. Clone the repository:
```bash
git clone 
cd 
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

Required environment variables:
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-min-32-chars
JWT_REFRESH_SECRET_KEY=your-refresh-secret-key-min-32-chars
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
BCRYPT_ROUNDS=12
ALGORITHM=HS256

# CORS (comma-separated origins)
CORS_ORIGINS=*

# Optional: Redis for token blacklisting
REDIS_URL=redis://localhost:6379
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
- ReDoc: `http://localhost:8000/redoc`
- Login: `http://localhost:8000/login`
- Register: `http://localhost:8000/register`
- Dashboard: `http://localhost:8000/dashboard`
- Profile: `http://localhost:8000/profile`

## API Endpoints

### Authentication

- `POST /auth/register` - Register a new user
  - Request: `{username, email, first_name, last_name, password, confirm_password}`
  - Response: User object with UUID
- `POST /auth/login` - Login and receive JWT tokens
  - Request: `{username, password}`
  - Response: `{access_token, refresh_token, token_type, expires_at, user_id, ...}`
- `POST /auth/token` - OAuth2 compatible token endpoint (form data)
  - Request: `username=...&password=...`
  - Response: `{access_token, token_type}`

### Profile Management

- `GET /profile/me` - Get current user profile
  - Headers: `Authorization: Bearer <token>`
  - Response: User profile with calculation count
- `PUT /profile/me` - Update user profile
  - Headers: `Authorization: Bearer <token>`
  - Request: `{username?, email?, first_name?, last_name?}` (at least one field)
  - Response: Updated user profile
- `POST /profile/change-password` - Change password
  - Headers: `Authorization: Bearer <token>`
  - Request: `{current_password, new_password, confirm_new_password}`
  - Response: `{message, updated_at}`

### Calculations

- `POST /calculations` - Create a new calculation
  - Headers: `Authorization: Bearer <token>`
  - Request: `{type: "addition|subtraction|multiplication|division", inputs: [numbers]}`
  - Response: Calculation object with computed result
- `GET /calculations` - List user's calculations
  - Headers: `Authorization: Bearer <token>`
  - Response: Array of calculation objects
- `GET /calculations/{id}` - Get specific calculation
  - Headers: `Authorization: Bearer <token>`
  - Response: Calculation object
- `PUT /calculations/{id}` - Update a calculation
  - Headers: `Authorization: Bearer <token>`
  - Request: `{inputs: [numbers]}`
  - Response: Updated calculation with recomputed result
- `DELETE /calculations/{id}` - Delete a calculation
  - Headers: `Authorization: Bearer <token>`
  - Response: 204 No Content

### Web Pages

- `GET /` - Home page
- `GET /login` - Login page
- `GET /register` - Registration page
- `GET /dashboard` - User dashboard (requires authentication)
- `GET /profile` - Profile management page (requires authentication)

### Health Check

- `GET /health` - Application health status
  - Response: `{status: "ok"}`

For detailed API documentation with request/response schemas, visit `/docs` or `/redoc` when the application is running.

## Testing

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests (fast, no database)
pytest tests/unit/ -v

# Integration tests (database required)
pytest tests/integration/ -v

# E2E tests (full application stack)
pytest tests/e2e/ -v

# Specific test file
pytest tests/unit/test_profile_logic.py -v

# Profile feature tests (all levels)
pytest tests/unit/test_profile_logic.py tests/integration/test_profile_routes.py tests/e2e/test_profile_e2e.py -v

# Run tests matching a pattern
pytest -k "password" -v

# Run tests with specific markers
pytest -m "slow" -v
```

### Run with Coverage

```bash
# Generate coverage report
pytest --cov=app --cov-report=html

# Generate terminal coverage report
pytest --cov=app --cov-report=term-missing

# Generate multiple report formats
pytest --cov=app --cov-report=html --cov-report=xml --cov-report=term
```

View coverage report:
```bash
# macOS/Linux
open htmlcov/index.html

# Windows
start htmlcov/index.html

# Or use a local server
python -m http.server -d htmlcov
```

### Test Coverage

The application includes comprehensive testing:
- **Unit Tests**: Schema validation, business logic, model operations, JWT handling
- **Integration Tests**: Database operations, route handlers, profile management
- **E2E Tests**: Complete user workflows with Playwright
  - Positive tests (successful operations)
  - Negative tests (error handling, validation)
  - Edge cases (invalid UUIDs, missing data, concurrent operations)

### Test Organization

- `tests/unit/`: Isolated component tests (schemas, models, auth)
- `tests/integration/`: Database and route integration tests
- `tests/e2e/`: Full application workflow tests
- `tests/conftest.py`: Shared fixtures and test configuration

## CI/CD Pipeline

### GitHub Actions Workflow

The pipeline consists of three jobs:

#### 1. Test Job
- Sets up PostgreSQL service container
- Caches pip dependencies for faster builds
- Installs dependencies including Playwright browsers
- Runs unit tests with coverage reporting
- Runs integration tests
- Runs E2E tests with Playwright
- Generates JUnit XML test results

#### 2. Security Job
- Depends on successful test job
- Builds Docker image
- Runs Trivy vulnerability scanner
- Checks for CRITICAL and HIGH severity vulnerabilities
- Ignores specified CVEs via `.trivyignore`
- Fails build if critical vulnerabilities found

#### 3. Deploy Job
- Only runs on main branch
- Requires test and security jobs to pass
- Uses production environment protection
- Builds multi-platform Docker image (linux/amd64, linux/arm64)
- Pushes to Docker Hub with tags:
  - `latest` - Most recent build
  - `<commit-sha>` - Specific version
- Uses Docker layer caching for faster builds

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

The Dockerfile includes:
- Python 3.10 slim base image
- System dependencies (gcc, libssl-dev, curl)
- Security updates
- Non-root user (appuser)
- Health check configuration
- Multi-stage optimization potential

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

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

Services included:
- **web**: FastAPI application (port 8000)
- **db**: PostgreSQL 17 (port 5432)
- **pgadmin**: Database management UI (port 5050)

### Production Deployment

For production deployment, consider:

1. **Environment Variables**: Use secrets management (AWS Secrets Manager, HashiCorp Vault)
2. **Database**: Managed PostgreSQL (AWS RDS, Google Cloud SQL, Azure Database)
3. **Reverse Proxy**: Nginx or Traefik for SSL termination
4. **Load Balancing**: Multiple application instances behind load balancer
5. **Monitoring**: Prometheus + Grafana for metrics
6. **Logging**: ELK stack or cloud logging services
7. **Backups**: Automated database backups
8. **CI/CD**: GitHub Actions pipeline already configured
9. **Container Registry**: Docker Hub, AWS ECR, Google GCR, Azure ACR
10. **Orchestration**: Kubernetes, Docker Swarm, or ECS for production workloads

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── python-app.yml          # CI/CD pipeline configuration
├── app/
│   ├── auth/
│   │   ├── dependencies.py         # Auth dependencies (get_current_user)
│   │   ├── jwt.py                  # JWT creation and password hashing
│   │   └── redis.py                # Token blacklisting (stub)
│   ├── core/
│   │   └── config.py               # App configuration and settings
│   ├── models/
│   │   ├── calculation.py          # Polymorphic calculation models
│   │   └── user.py                 # User model with auth methods
│   ├── routes/
│   │   └── profile.py              # Profile management routes
│   ├── schemas/
│   │   ├── calculation.py          # Calculation Pydantic schemas
│   │   ├── profile.py              # Profile Pydantic schemas
│   │   ├── token.py                # Token Pydantic schemas
│   │   └── user.py                 # User Pydantic schemas
│   ├── database.py                 # Database config and session management
│   ├── database_init.py            # DB initialization script
│   └── main.py                     # Application entry point
├── static/
│   ├── css/
│   │   └── style.css               # Custom styles and animations
│   └── js/
│       └── script.js               # Client-side utilities
├── templates/
│   ├── dashboard.html              # User dashboard with calculations
│   ├── index.html                  # Home page
│   ├── layout.html                 # Base Jinja2 template
│   ├── login.html                  # Login page
│   ├── profile.html                # Profile management page
│   └── register.html               # Registration page
├── tests/
│   ├── e2e/
│   │   ├── test_bread_operations.py    # BREAD operations E2E tests
│   │   ├── test_edge_cases.py          # Edge case E2E tests
│   │   ├── test_fastapi_calculator.py  # Main E2E tests
│   │   └── test_profile_e2e.py         # Profile E2E tests
│   ├── integration/
│   │   ├── test_main_routes.py         # Route integration tests
│   │   └── test_profile_routes.py      # Profile integration tests
│   ├── unit/
│   │   ├── test_auth_dependencies.py   # Auth dependency tests
│   │   ├── test_calculation_models.py  # Calculation model tests
│   │   ├── test_config_and_database.py # Config tests
│   │   ├── test_jwt.py                 # JWT and password tests
│   │   ├── test_profile_logic.py       # Profile schema tests
│   │   ├── test_redis.py               # Redis stub tests
│   │   ├── test_schemas.py             # Schema validation tests
│   │   └── test_user_model.py          # User model tests
│   └── conftest.py                 # Pytest fixtures and config
├── .env.example                    # Environment variable template
├── .gitignore                      # Git ignore rules
├── .trivyignore                    # Trivy scanner exceptions
├── docker-compose.yml              # Docker services configuration
├── Dockerfile                      # Docker image definition
├── init-db.sh                      # Database initialization script
├── pytest.ini                      # Pytest configuration
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Security Considerations

- JWT tokens with configurable expiration (access: 30min, refresh: 7 days)
- Bcrypt password hashing with configurable rounds (default: 12)
- Password strength validation (min 8 chars, uppercase, lowercase, digit, special char)
- SQL injection prevention via SQLAlchemy ORM and parameterized queries
- CORS configuration for cross-origin requests
- Non-root user in Docker container (appuser:appgroup)
- Input validation with Pydantic schemas
- Token-based authorization with dependency injection
- Unique constraints on username and email fields
- Cascade deletion to maintain referential integrity
- Health check endpoint for monitoring
- Environment variable configuration for secrets
- HTTPOnly cookie support ready (not implemented)
- HTTPS-ready deployment configuration

## Performance & Scalability

### Database Optimizations
- Indexed columns: user_id, type, username, email
- Connection pooling via SQLAlchemy
- Lazy loading for relationships
- UUID primary keys for distributed systems

### Application Performance
- Async-ready with FastAPI
- Dependency injection for efficient resource management
- Pydantic validation (compiled with Cython)
- Static file serving via FastAPI StaticFiles

### Scalability Considerations
- Stateless JWT authentication (horizontal scaling friendly)
- PostgreSQL supports read replicas
- Docker multi-platform builds (AMD64/ARM64)
- Uvicorn with multiple workers (`--workers 4`)
- Ready for load balancing and CDN integration

### Monitoring & Observability
- Health check endpoint (`/health`)
- Structured logging ready
- Docker healthcheck configured
- Test coverage reporting
- CI/CD pipeline monitoring

## Development Guidelines

### Adding New Features

1. **Create models** in `app/models/` with proper relationships
2. **Define Pydantic schemas** in `app/schemas/` with validators
3. **Implement routes** in `app/routes/` or `app/main.py` with proper auth
4. **Write unit tests** in `tests/unit/` for business logic
5. **Write integration tests** in `tests/integration/` for database operations
6. **Write E2E tests** in `tests/e2e/` for complete workflows
7. **Update documentation** in README and docstrings

### Code Style

- Follow PEP 8 guidelines
- Use type hints consistently
- Write comprehensive docstrings for public functions and classes
- Keep functions focused and small (single responsibility)
- Use meaningful variable names
- Add comments for complex logic
- Use Pydantic validators for input validation
- Handle errors with appropriate HTTP status codes

### Database Migrations

- Models use SQLAlchemy declarative base
- Automatic table creation on startup (development)
- Use `database_init.py` for manual initialization
- Consider Alembic for production migrations

### Testing Best Practices

- Use pytest fixtures for test data
- Mock external dependencies
- Test positive and negative cases
- Test edge cases and boundary conditions
- Aim for high code coverage (>80%)
- Use descriptive test names
- Clean up test data in teardown

## Troubleshooting

### Common Issues

**Database Connection Error:**
- Verify PostgreSQL is running (`docker ps` or system service)
- Check DATABASE_URL format in environment
- Ensure database exists and is accessible
- Check network connectivity in Docker

**Authentication Errors:**
- Verify JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY are set
- Check token hasn't expired (default: 30 minutes)
- Ensure proper Authorization header format: `Bearer <token>`
- Clear browser localStorage if tokens are corrupted

**Tests Failing:**
- Ensure PostgreSQL test service is running
- Verify test database exists and is clean
- Check pytest.ini configuration
- Run `pytest -v` for verbose output
- Check for port conflicts (default: 8000)

**Docker Issues:**
- Clear Docker cache: `docker system prune -a`
- Rebuild images: `docker-compose build --no-cache`
- Check logs: `docker-compose logs -f`
- Ensure ports 8000, 5432, 5050 are available

**Frontend Issues:**
- Check browser console for JavaScript errors
- Verify API endpoints are accessible
- Clear browser cache and localStorage
- Check network tab for failed requests

**Password Validation:**
- Must be at least 8 characters
- Requires uppercase, lowercase, digit, and special character
- Special characters: `!@#$%^&*()_+-=[]{}|;:,.<>?`
