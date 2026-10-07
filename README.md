# Whishlist.io

Account-free wishlist / gift registry.

## Features
- No registration, email or password.
- Private high-entropy management link.
- Public share link.
- Add products from any store with URL, price, note and priority.
- Guests can reserve gifts without an account.
- Owner cannot see who made a reservation.
- Owner can unreserve gifts.
- SQLite persistence.
- Render-ready deployment.

## Run
```bash
npm install
npm start
```
Then open http://localhost:3000. (published on https://whishlist-io.onrender.com/)

## Security
The management URL is the credential. Anyone who has it can edit the list. There is deliberately no account recovery.

## Roadmap
Product metadata previews, drag-and-drop, QR codes, JSON export/import, and optional anonymous PIN recovery.
