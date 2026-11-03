# Voxora

**Connect. Chat. Play.** A free community chat platform designed for Cloudflare.

Voxora is an open-source Discord-style community app. This first milestone includes a responsive interactive frontend and a Cloudflare Workers + Static Assets project scaffold.

## Stack
- Cloudflare Workers + Static Assets — website and API
- Cloudflare D1 — persistent relational data (database setup is the next step)
- Cloudflare Durable Objects — real-time rooms (next milestone)
- Cloudflare R2 — file uploads (planned)

## Local development
```bash
npm install
npm run dev
```
The frontend demo works before the database is created. Database-backed API routes will clearly report when D1 is not configured.

## Deploy to Cloudflare
1. Create a D1 database named `voxora-db`.
2. Copy its database ID into the `VOXORA_DB` binding in `wrangler.toml`.
3. Run `npm run db:migrate:remote`.
4. Run `npm run deploy`.

Cloudflare dashboard: https://dash.cloudflare.com/
Workers docs: https://developers.cloudflare.com/workers/
Static Assets docs: https://developers.cloudflare.com/workers/static-assets/

## Roadmap
- [x] Responsive Voxora UI shell
- [x] Interactive demo channels, messages, and server creation
- [x] Cloudflare Workers + Static Assets scaffold
- [x] D1 schema migration
- [ ] Secure registration and login
- [ ] Persistent servers, channels, and messages
- [ ] Real-time chat with Durable Objects
- [ ] Friends and direct messages
- [ ] Roles, permissions, and moderation
- [ ] R2 file uploads
- [ ] Voice and video calling

No premium tier or paywall is planned. Cloudflare service quotas and provider limits still apply; unlimited free hosting cannot be guaranteed.

## License
MIT
