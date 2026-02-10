# SusuKonnect Production Architecture (Next Pass)

SusuKonnect now includes a split production-oriented architecture while preserving the same MVP behavior from the first pass:

- **React Native frontend** (`apps/mobile`)
- **Node backend implementation** (`services/api-node`)
- **Laravel parity backend implementation** (`services/api-laravel`)
- **Shared domain contracts/types** (`packages/shared`)
- **OpenAPI contract** (`docs/openapi/susukonnect-v1.yaml`)

The original static MVP UI remains in the repo root as a legacy reference:

- `index.html`
- `styles.css`
- `app.js`

## Monorepo Layout

```text
apps/
  mobile/                # Expo React Native client
services/
  api-node/              # Primary backend implementation (TypeScript/Express)
  api-laravel/           # Laravel parity controllers/services/policies/tests
packages/
  shared/                # Shared types/constants/domain models
docs/
  openapi/               # API contract
```

## Implemented Production-Path Capabilities

### Shared business behavior (preserved MVP logic)
- User onboarding, auth, RBAC, MFA, biometric flow
- KYC lifecycle and admin review
- Group creation/joining/approvals
- Contributions with grace/late/reminder logic
- Payout orchestration:
  - fixed rotation
  - voting-based
  - priority-based claims
- Chat, notifications, calendar events
- Admin compliance:
  - KYC queue
  - fraud flags
  - disputes
  - group suspension/reactivation
  - export + audit chain

### Real provider adapter support (Node backend)
- **Stripe**:
  - contribution charging
  - payout transfer path (connected-account capable)
  - Stripe Identity KYC session support
- **PayPal**:
  - OAuth token flow
  - order create/capture
  - payouts API flow

Provider behavior is env-driven with simulation fallback for local development.

## Quick Start

### 1) Install workspace dependencies

```bash
npm install
```

### 2) Start Node backend

```bash
cp services/api-node/.env.example services/api-node/.env
npm run dev:api
```

### 3) Start React Native app (Expo)

```bash
EXPO_PUBLIC_API_BASE_URL=http://localhost:4000/v1 npm run dev:mobile
```

## Demo Credentials

- Admin: `admin@susukonnect.app` / `Admin@2026`
- Leader: `leader@susukonnect.app` / `Leader@2026`
- Member: `member@susukonnect.app` / `Member@2026`

## Environment Highlights (Node)

See: `services/api-node/.env.example`

Important toggles:

- `PAYMENTS_LIVE_MODE=true|false`
- `KYC_LIVE_MODE=true|false`
- `EXPOSE_MFA_CODES=true|false`
- `STRIPE_SECRET_KEY=...`
- `PAYPAL_CLIENT_ID=...`
- `PAYPAL_CLIENT_SECRET=...`

## Contract Parity

Use the API contract in `docs/openapi/susukonnect-v1.yaml` as the source of truth for:

- Node route implementation
- Laravel route/controller implementation
- Mobile client integration
