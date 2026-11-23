# LandConnect – Land Marketplace (Live / PWA version)

Node.js + Express backend (REST + WebSocket) that also serves the full LandConnect web app (installable PWA).
Database: SQLite locally, PostgreSQL when `DATABASE_URL` is set. Photos are stored in the database. Audio/video calls use WebRTC.

## Features
- Register / login with roles Buyer, Seller, Broker (JWT, bcrypt) and server-side role rules
- Community page: search, list view, map view (OpenStreetMap / Leaflet)
- Listings (seller/broker): create, edit, delete, up to 10 photos, price, area, location, "hide exact location"
- Realtime chat over WebSocket with delivered / read ticks, profile pictures
- Meeting rooms: schedule, join as video/audio call, cancel
- In-app audio/video calls (WebRTC): accept, reject, end, mute, speaker, camera
- Privacy: "who can call me", block / unblock, emails and phone numbers are never shown to others
- Installable on phones (PWA): Android Chrome "Install app", iPhone Safari "Add to Home Screen"

## Run locally
```
npm install
cp .env.example .env     (Windows: copy .env.example .env)
npm start
```
Open http://localhost:8000 (camera/mic for calls need https, or localhost).

## Deploy free (Render + Neon + UptimeRobot)
1. Push this folder to GitHub (do not push `.env` or `node_modules`; `.gitignore` already skips them). No `npm install` is needed before pushing.
2. Neon (neon.com): create a project, copy the connection string -> `DATABASE_URL`.
3. Render (render.com): New -> Web Service -> select the repo.
   Build `npm install` · Start `npm start` · Instance Free · Health check path `/health`.
   Environment variables:
   - `NODE_ENV=production`
   - `SECRET_KEY` = long random string (40+ chars)
   - `DATABASE_URL` = Neon string
   - `TURN_URLS`, `TURN_USERNAME`, `TURN_CREDENTIAL` = free TURN from metered.ca (needed for calls across different networks / mobile data)
4. Open `https://<name>.onrender.com` and share the link.
5. UptimeRobot (free): HTTP monitor on `https://<name>.onrender.com/health` every 5 minutes so the free service does not sleep.

## Notes
- Calls ring only while the app is open (no push notifications / background ringing).
- Free Render services sleep after 15 minutes without traffic and take about a minute to wake up.
- Neon free storage is 1 GB per project; photos count against it.

## API summary
POST /auth/register · POST /auth/login (form: username=email, password) · GET /me · PUT /me/privacy · PUT /me/profile · POST/DELETE /me/avatar · GET /users/:id · GET /buyers
GET/POST /listings · PUT/DELETE /listings/:id · POST /upload · GET /uploads/:name
GET /conversations · GET /messages/:uid · GET/POST /meetings · POST /meetings/:id/cancel
GET /blocks · POST/DELETE /blocks/:id · GET /ice · GET /health · WS /ws?token=JWT
