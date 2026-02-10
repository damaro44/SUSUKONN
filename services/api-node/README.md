# SusuKonnect Node API

Production-oriented backend implementation for SusuKonnect MVP behavior.

## Capabilities

- Auth + RBAC + MFA challenge flow
- KYC submission + admin review
- Group creation/joining + leader approvals
- Contribution collection with provider charge calls
- Payout orchestration (fixed, voting, priority logic)
- Chat, calendar, notifications
- Admin compliance operations (fraud flags, disputes, export, audit)
- Real provider adapters:
  - Stripe (payments, Stripe Identity KYC)
  - PayPal (orders + payouts)

## Run

```bash
npm install
npm run dev --workspace @susukonnect/api-node
```

Server starts on `http://localhost:4000` by default.

## Environment

Copy:

```bash
cp services/api-node/.env.example services/api-node/.env
```

Use sandbox provider keys first, then flip:

- `PAYMENTS_LIVE_MODE=true`
- `KYC_LIVE_MODE=true`

## Demo users

- `admin@susukonnect.app` / `Admin@2026`
- `leader@susukonnect.app` / `Leader@2026`
- `member@susukonnect.app` / `Member@2026`
