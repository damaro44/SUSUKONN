# SusuKonnect Laravel Backend Scaffold

This directory provides a Laravel-aligned implementation path with the same API contract used by:

- `services/api-node` (primary implementation)
- `apps/mobile` (React Native client)

## Purpose

- Keep Node and Laravel backends contract-compatible.
- Enable migration or dual-team development without breaking mobile flows.
- Mirror MVP behavior semantics: auth, KYC, groups, contributions, payouts, chat, notifications, admin compliance.

## API Contract Source of Truth

- `docs/openapi/susukonnect-v1.yaml`

## Expected Laravel Structure

- `routes/api.php` - endpoint map and middleware wiring
- `app/Http/Controllers/*` - thin controllers
- `app/Services/Domain/*` - business logic parity with Node engine
- `app/Services/Providers/*` - Stripe/PayPal/KYC integrations
- `app/Policies/*` - RBAC authorization policies

## Suggested packages

- `laravel/sanctum` for token auth
- `stripe/stripe-php` for Stripe payments + Stripe Identity
- PayPal REST integration via Guzzle + OAuth token service

## Next steps

1. Create Laravel project in this folder (or link existing repo).
2. Copy endpoint map from `routes/api.php`.
3. Implement domain services mirroring Node behavior rules exactly.
4. Reuse OpenAPI contract for request/response validation tests.
