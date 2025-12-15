# Job Applicant Tracker

Track your job applications across all your devices.

## Quick Start (Local)

```bash
cd server
npm install
npm start
```

Open http://localhost:3000

---

## Deploy to Railway

1. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
2. Select `Anish2905/JobScheduleTracker`
3. Click on the service → Settings → Set **Root Directory** to `server`
4. Settings → Networking → Generate Domain → Port: `3000`
5. Done! Access your app at the generated URL

---

## Deploy to Render

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Settings:
   - **Root Directory:** `server`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Create Web Service → Get your public URL

---

## Project Structure

```
JobScheduleTracker/
├── server/
│   ├── server.js       # Express API
│   ├── database.js     # SQLite
│   └── package.json
├── public/
│   └── index.html      # Frontend
└── README.md
```

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/applications` | List all |
| POST | `/api/applications` | Create |
| PUT | `/api/applications/:id` | Update |
| DELETE | `/api/applications/:id` | Delete |
