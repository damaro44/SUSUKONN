# SusuKonnect React Native App (Expo)

Mobile frontend for SusuKonnect MVP production architecture.

## What it covers

- Secure login + registration
- MFA challenge handling for sensitive actions
- Role-aware tabs (member/leader/admin)
- Dashboard
- Groups (create, join, select)
- Contributions (pay)
- Payout workflow (request, approve, confirm, release)
- Group chat
- Calendar events
- Notification center
- Security controls (KYC, auth preferences, payment methods)
- Admin compliance panel (overview + KYC review)

## Configure backend URL

Set Expo public env:

```bash
EXPO_PUBLIC_API_BASE_URL=http://localhost:4000/v1
```

## Run

```bash
npm install
npm run start --workspace @susukonnect/mobile
```

Then launch on iOS/Android simulator via Expo.
