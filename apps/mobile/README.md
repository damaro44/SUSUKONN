# Eclair Technology Assistance Mobile MVP (Expo)

Single-codebase mobile/web app for **iOS, Android, and Web**.

## Core features implemented

- Live authentication with Eclair API (`/auth/login`)
- Role-based permissions (frontend RBAC)
- Role capabilities panel (allowed vs restricted actions)
- Dashboard (readiness/risk/open findings/training programs)
- Compliance audit creation + list
- Training plan creation + list
- Report export triggers (CSV/PDF)
- Bilingual UI (English/French)

## Environment

Use the Eclair API URL as Expo public env:

```bash
EXPO_PUBLIC_API_BASE_URL=http://localhost:4100/v1
```

## Run (all platforms)

```bash
npm install
npm run start --workspace @susukonnect/mobile
```

Then choose:

- `w` for Web
- `i` for iOS simulator
- `a` for Android emulator

## Demo credentials

- `admin@eclair.tech` / `Admin@2026`
- `compliance@eclair.tech` / `Compliance@2026`
- `auditor@eclair.tech` / `Auditor@2026`
- `training@eclair.tech` / `Training@2026`
