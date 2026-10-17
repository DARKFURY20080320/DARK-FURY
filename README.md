# DARK FURY TOPUP CENTER — Full-stack starter

## Run locally
1. Install Node.js 20 LTS or later.
2. Extract ZIP; open terminal in folder.
3. Copy `.env.example` to `.env`.
4. Set `SESSION_SECRET` to a long random secret and set a strong `ADMIN_PASSWORD`.
5. Run `npm install`, then `npm start`.
6. Open `http://localhost:3000`.

Admin login email defaults to `mohamedrahid716@gmail.com`; password is the value in `.env`. If the user already exists in `darkfury.sqlite`, the initial password/role is not reset. For local testing only, stop server and delete the database file to recreate it (this deletes all data).

## Included
Responsive black/red SG storefront, customer registration/login, SQLite storage, wallet ledger, deposit requests, admin approve/reject, product price management, order history, order submission and basic security headers/rate limits.

## Not live / safety notes
- Not production ready: add CSRF protection, production session store, HTTPS, monitoring, backups and security review.
- PayHere is not integrated. No payment is taken; bank/EZ Cash deposit requests require independent manual verification before admin approval.
- No reseller API is connected. Orders are saved as `queued_manual`; no automatic top-up is sent. Wallet is debited when order is created, so do not accept real orders until provider delivery and a safe failure/refund process are implemented.
- UID lookup is not integrated.
- No direct official Garena API access is claimed. Obtain authorized provider docs and credentials; do not guess endpoints or advertise instant delivery until tested.
- Sample prices need updating. `mohamedrahid716@gmail.com` is the app admin login identifier, not a Google account connection. Google Sign-In requires separate OAuth/Firebase setup.
- Never request game passwords or OTPs. Keep API secrets in server environment only.
