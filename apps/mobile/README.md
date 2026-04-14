# Eclair Technology Assistance Mobile MVP (Expo)

Single-codebase app for **iOS, Android, and Web**.

## Core features implemented

- Live authentication with Eclair API (`/auth/login`)
- Secure persistent session storage (token + user) via Expo SecureStore
- Persistent language preference (EN/FR) via AsyncStorage
- Role-based permissions (frontend RBAC)
- Role capabilities panel (allowed vs restricted actions)
- Dashboard (readiness/risk/open findings/training programs)
- Compliance audit creation + list
- Training plan creation + list
- Report export triggers (CSV/PDF)

## Environment

Set API URL for Expo runtime:

```bash
EXPO_PUBLIC_API_BASE_URL=http://localhost:4100/v1
```

## Local run (all platforms)

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

## Build installable artifacts with EAS

The repo includes `eas.json` profiles.

1) Install/login EAS CLI:

```bash
npm install -g eas-cli
eas login
```

2) Build Android APK (preview/internal):

```bash
eas build --platform android --profile preview
```

3) Build iOS IPA (production):

```bash
eas build --platform ios --profile production
```

4) Optional both at once:

```bash
eas build --platform all --profile production
```

> Update `EXPO_PUBLIC_API_BASE_URL` values in `eas.json` to your real backend URL before production builds.
