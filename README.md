# Secure Banking Application

A full-stack secure online banking application built for the Introduction to Cybersecurity final project. The system demonstrates comprehensive cybersecurity principles including authentication, cryptography, input validation, audit logging, and secure file handling.

---

## Architecture

```
Secure-Banking-API/                  ← GitHub Repository Root
│
├── SecureBankingAPI/                ← C# .NET Core 10 Web API (Backend)
│   ├── Controllers/                 ← API endpoints
│   ├── Services/                    ← Business logic
│   ├── Middleware/                  ← Security headers, exception handling
│   ├── Models/                      ← Database models
│   ├── DTOs/                        ← Request/response objects
│   ├── Data/                        ← EF Core DbContext
│   ├── Configuration/               ← Settings classes
│   ├── Migrations/                  ← EF Core database migrations
│   ├── Program.cs                   ← App startup and middleware pipeline
│   ├── appsettings.json             ← Configuration
│   └── SecureBankingAPI.csproj      ← NuGet packages
│
└── SecureBankingFlask/              ← Python Flask Frontend (within same repo)
    ├── routes/                      ← Page routes (auth, dashboard, transactions, admin)
    ├── services/                    ← API client (communicates with C# backend)
    ├── templates/                   ← HTML pages
    ├── static/css/                  ← Stylesheets
    └── app.py                       ← Flask entry point
```

### How they connect

```
User (Browser)
      │  HTTP
      ▼
Python Flask (port 5001)      ← handles UI, sessions, forms
      │  HTTP REST API calls
      ▼
C# .NET Core API (port 5000)  ← handles all security logic
      │  EF Core parameterized queries
      ▼
SQL Server LocalDB            ← database
```

The Flask frontend is a lightweight UI layer. All security-sensitive operations (password hashing, JWT validation, transaction signing, file scanning) happen exclusively in the C# backend. Flask never touches the database directly.

---

## Security Features

| Feature | Implementation |
|---|---|
| Password hashing | BCrypt work factor 12 with built-in salt |
| JWT authentication | HMAC-SHA256 signed, 30 min expiry |
| MFA / TOTP | OTP.NET, 30s windows, AES-encrypted secret |
| Account lockout | 5 failed attempts → 15 min lockout |
| Role-based access | Customer / Teller / Admin policies |
| Parameterized queries | EF Core (all queries parameterized by default) |
| Input validation | Data annotations on all DTOs |
| XSS prevention | JSON-only responses, output encoding in templates |
| Transaction signing | HMAC-SHA256 per transaction for tamper detection |
| File upload security | Extension + MIME + magic number validation |
| Virus scan simulation | EICAR test string detection |
| Encryption at rest | AES-256 for uploaded files |
| Audit logging | Hash-chained append-only logs (SHA-256) |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Rate limiting | 5 login attempts/min, 100 general requests/min |
| Error handling | Generic errors only — no stack traces exposed |

---

## Setup & Running

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- [Python 3.x](https://python.org/downloads) — check **Add to PATH** during install
- SQL Server LocalDB (included with Visual Studio)

### 1. Clone the repository
```bash
git clone https://github.com/Zaid-software/Secure-Banking-API.git
cd Secure-Banking-API
```

### 2. Run the C# Backend

```bash
cd SecureBankingAPI
dotnet restore
dotnet ef migrations add InitialCreate   # skip if Migrations/ folder already exists
dotnet run
```

Wait for:
```
Now listening on: http://localhost:5000
```

The database is created automatically on first run.

### 3. Run the Python Flask Frontend

Open a **second terminal**:

```bash
cd SecureBankingFlask
pip install flask requests python-dotenv
python app.py
```

Wait for:
```
Running on http://127.0.0.1:5001
```

### 4. Open the app

| URL | What it is |
|---|---|
| `http://127.0.0.1:5001` | Banking website (Flask frontend) |
| `http://localhost:5000/swagger` | API documentation and testing |

---

## API Endpoints

### Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | None | Register new customer |
| POST | `/api/auth/login` | None | Login, returns JWT |
| POST | `/api/auth/mfa/setup` | JWT | Generate TOTP QR code |
| POST | `/api/auth/mfa/verify` | JWT | Enable MFA |

### Transactions
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/transaction/account` | JWT | Get account balance |
| GET | `/api/transaction/history` | JWT | Last 50 transactions |
| POST | `/api/transaction/deposit` | JWT | Deposit funds |
| POST | `/api/transaction/withdraw` | JWT | Withdraw funds |
| POST | `/api/transaction/transfer` | JWT | Transfer to another account |

### File Upload
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/fileupload/upload` | JWT | Upload check image |
| GET | `/api/fileupload/{id}` | JWT | Download your file |

### Admin (Admin role only)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/admin/users` | Admin | List all users |
| PUT | `/api/admin/users/{id}/role` | Admin | Update user role |
| POST | `/api/admin/users/{id}/unlock` | Admin | Unlock locked account |
| GET | `/api/admin/audit-logs` | Admin | View audit logs |
| GET | `/api/admin/audit-logs/verify` | Admin | Verify log integrity |

---

## Project Structure Detail

### Backend — SecureBankingAPI/

```
Controllers/
├── AuthController.cs          register, login, MFA endpoints
└── Controllers.cs             Transaction, FileUpload, Admin controllers

Services/
├── AuthService.cs             BCrypt verify, lockout logic
├── TokenService.cs            JWT generation
├── TransactionService.cs      Deposit/withdraw/transfer + HMAC signing
├── FileUploadService.cs       Magic number check, AES-256, virus scan
├── AuditService.cs            Hash-chained audit log
└── OtherServices.cs           TotpService, UserService

Middleware/
└── Middleware.cs              Security headers, global exception handler, audit logging

Models/
└── Models.cs                  User, Account, Transaction, AuditLog, FileUpload

DTOs/
└── DTOs.cs                    All request/response objects with validation
```

### Frontend — SecureBankingFlask/

```
routes/
├── auth.py                    Login, register, logout, MFA
├── dashboard.py               Account balance and recent transactions
├── transactions.py            Deposit, withdraw, transfer, upload
└── admin.py                   User management, audit logs

services/
└── api_client.py              All HTTP calls to C# backend

templates/
├── base.html                  Navbar, flash messages
├── auth/                      Login, register, MFA pages
├── dashboard/                 Main dashboard
├── transactions/              All transaction pages
├── admin/                     Admin panel pages
└── errors/                    404, 403, 500 pages
```

---

## Git Branch Strategy

```
main        ← final submission
  └── develop  ← all active development
```

---

## NuGet Packages (Backend)

| Package | Purpose |
|---|---|
| BCrypt.Net-Next | Password hashing (bcrypt, work factor 12) |
| Otp.NET | TOTP/MFA generation and verification |
| AspNetCoreRateLimit | IP-based rate limiting |
| Microsoft.AspNetCore.Authentication.JwtBearer | JWT authentication |
| Microsoft.EntityFrameworkCore.SqlServer | ORM with parameterized queries |
| Swashbuckle.AspNetCore | Swagger API documentation |

## Python Packages (Frontend)

| Package | Purpose |
|---|---|
| flask | Web framework |
| requests | HTTP calls to C# backend |
| python-dotenv | Environment variable loading |
