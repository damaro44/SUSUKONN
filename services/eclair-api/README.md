# Eclair API

Production-oriented backend API for Eclair Technology Assistance.

## Capabilities

- JWT authentication
- Role-based access control (RBAC)
- Compliance audit and training planning endpoints
- CSV and PDF compliance report exports

## Quick start

```bash
cp .env.example .env
npm run dev --workspace @eclair/api
```

Base URL: `http://localhost:4100/v1`

## Demo users

- `admin@eclair.tech` / `Admin@2026` (role: `super_admin`)
- `compliance@eclair.tech` / `Compliance@2026` (role: `compliance_officer`)
- `training@eclair.tech` / `Training@2026` (role: `training_manager`)
- `auditor@eclair.tech` / `Auditor@2026` (role: `auditor`)

## Report export

- `GET /v1/reports/compliance?format=csv`
- `GET /v1/reports/compliance?format=pdf`

The endpoint streams files with proper download headers.
