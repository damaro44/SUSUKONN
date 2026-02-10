# SusuKonnect Laravel Backend (Parity Implementation)

This directory now contains a full Laravel-oriented parity implementation path with the same API contract used by:

- `services/api-node` (primary implementation)
- `apps/mobile` (React Native client)

## Purpose

- Keep Node and Laravel backends contract-compatible.
- Enable migration or dual-team development without breaking mobile flows.
- Mirror MVP behavior semantics from the Node backend:
  - auth + MFA
  - KYC lifecycle
  - groups + joins + approvals
  - contributions + payout orchestration
  - chat + notifications + calendar
  - admin compliance + audit/export

## API Contract Source of Truth

- `docs/openapi/susukonnect-v1.yaml`

## Implemented Structure

- `routes/api.php` - endpoint map compatible with Node contract
- `app/Http/Controllers/*` - concrete controller logic using domain engine
- `app/Services/Domain/DomainEngineService.php` - full parity business engine
- `app/Services/Domain/DomainStateRepository.php` - in-memory state persistence
- `app/Services/Domain/SeedStateFactory.php` - deterministic seed data
- `app/Services/Providers/*` - Stripe/PayPal/KYC provider adapters
- `app/Policies/*` - RBAC policies
- `app/Providers/*` - service bindings and auth gates
- `tests/Feature` and `tests/Unit` - parity tests

## Composer Packages

- `laravel/framework`
- `stripe/stripe-php`
- `phpunit/phpunit`

## Run (inside a PHP/Laravel environment)

1. Install dependencies:

```bash
composer install
```

2. Run tests:

```bash
vendor/bin/phpunit --configuration phpunit.xml
```

3. Wire providers in Laravel app bootstrap if needed:
   - `App\Providers\DomainServiceProvider`
   - `App\Providers\AuthServiceProvider`

## Notes

- This implementation intentionally keeps state in-memory for parity prototyping.
- For production, replace `DomainStateRepository` with database-backed repositories (Eloquent + migrations) while preserving service-level rules.
