# SusuKonnect MVP App Foundation

SusuKonnect is a fintech MVP that digitizes traditional rotating savings circles (SuSu, Esusu, Sou-Sou, ROSCA) with secure workflows, transparent records, and compliance controls.

This implementation is a complete static web app foundation (PWA style) that covers the requested scope of work modules and business-plan context.

## Included MVP Modules

### 1) User onboarding and verification
- Email + phone + password registration
- Terms and Savings Agreement acceptance required
- Role-aware onboarding (member / leader / admin)
- KYC submission (ID type, tokenized ID number, DOB, selfie token, address)
- Admin KYC review and approval/rejection
- Verified badge handling

### 2) Authentication and security controls
- Role-based access control (RBAC)
- Device fingerprinting and trusted devices
- MFA modal flow for:
  - New device login
  - Contribution payments
  - Payout approvals
  - Payout release
  - Payment method changes
- Biometric login simulation for trusted devices
- Session timeout enforcement
- Brute-force login lockout

### 3) Savings group lifecycle
- Group creation with:
  - Name, description, location, community tag
  - Monthly contribution amount
  - Currency
  - Member cap
  - Grace period days
  - Rules
  - Join approval requirement toggle
- Group search/filter:
  - Name
  - Community
  - Location
  - Contribution amount
  - Start date
- Invite link generation/copy
- Join request and leader/admin review
- Group suspension/reactivation by admin

### 4) Contribution engine
- Per-cycle contribution records
- Manual payment with tokenized methods
- Auto-debit preference
- Grace period handling
- Late-status escalation
- Leader reminder actions
- Smart auto reminders
- Transparent member payment table

### 5) Payout workflow
- Payout reasons (all requested values + custom reason)
- Payout order logic:
  - Fixed rotation
  - Voting-based
  - Priority-based (reason scoring)
- Payout request gate:
  - All contributions must be paid
  - KYC verified recipient
- Approval model:
  - Leader approval (if required)
  - Admin approval for high-value payouts
- Recipient MFA confirmation
- Final release action with MFA
- Platform fee (1.5%) and net payout calculation
- Automatic next-cycle progression
- Group completion milestone and chat archive

### 6) In-app communication
- Group-specific chat
- Leader/admin announcement mode
- Message pin/unpin moderation
- Auto-archive for completed groups

### 7) Calendar and notifications
- Due dates
- Grace deadlines
- Payout checkpoints
- Milestones
- Notification center with mark read / mark all read

### 8) Admin + compliance dashboard
- Pending KYC queue
- Transaction monitoring summary
- Fraud flag creation
- Dispute filing and resolution
- Group controls
- Immutable audit log table (hash chain)
- Report export:
  - JSON
  - CSV
  - Audit-chain JSON

## Branding

- `assets/susukonnect-mark.svg` (app icon mark)
- `assets/susukonnect-logo.svg` (header logo with tagline)
- Colors and typography styled to match the provided SusuKonnect branding direction.

## File Structure

- `index.html` - App shell and MFA modal
- `styles.css` - UI system and responsive layout
- `app.js` - Full application logic and data model
- `manifest.json` - PWA manifest
- `service-worker.js` - Offline cache behavior
- `assets/` - SusuKonnect logo assets

## Demo Credentials

- Admin: `admin@susukonnect.app` / `Admin@2026`
- Leader: `leader@susukonnect.app` / `Leader@2026`
- Member: `member@susukonnect.app` / `Member@2026`

## Local Run

Open `index.html` in a browser, or serve statically:

```bash
python3 -m http.server 8080
```

Then visit: `http://localhost:8080`

## Notes

- This MVP foundation focuses on end-to-end product flow and controls.
- Real production deployment should replace simulated flows with:
  - Real KYC provider APIs
  - Real payment processor APIs
  - Real MFA channels (SMS/authenticator)
  - Server-side encryption, storage, and compliance infrastructure
