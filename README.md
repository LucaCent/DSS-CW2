# DSS-CW2 — Secure Development Project

## Local setup

1. Clone the repo and switch to the dev branch:
	git clone https://github.com/LucaCent/DSS-CW2.git
	cd DSS-CW2
	git checkout dev
	git checkout -b feature/your-card-name
	npm install

2. Create your local `.env` file using `.env.example` as a template.
	Ask the group for the shared values of `SESSION_SECRET`, `PEPPER`, and `ENCRYPTION_KEY`.

3. Generate your own self-signed cert for HTTPS (required — each dev generates their own):
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

4. Run the users table migration:
	psql -U postgres -h localhost -d dss_blog -f migrations/001_create_users.sql

5. Start the server:
	node server.js
	Open https://localhost:3000 — click through the cert warning (expected for self-signed).

## Running tests
npm test
## Notes

- Never commit `.env`, `key.pem`, or `cert.pem` — all are gitignored.
- One Trello card = one feature branch = one PR into `dev`.
- Always pull latest `dev` before starting a new card.