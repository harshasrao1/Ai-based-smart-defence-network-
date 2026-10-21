# Deploying Smart Defence on Vercel

This repository is configured to be deployed on **Vercel**.

---

## Architecture Overview

The system is a full-stack application composed of:
1. **Frontend**: Static single-page application (`frontend/index.html`, `styles.css`, `app.js`).
2. **Backend**: Python Flask REST API with Random Forest models (`scikit-learn`), traffic simulation, rule detection, and SQLite.

You have two deployment strategies depending on your requirements:

| Strategy | Frontend | Backend | Best For |
| :--- | :--- | :--- | :--- |
| **Option A (All-in-One Serverless)** | Vercel CDN | Vercel Serverless Function (`api/index.py`) | Quick demo, simulation mode, zero extra accounts |
| **Option B (Vercel Frontend + Persistent Backend)** | Vercel CDN | Render / Railway / Fly.io / VPS | Full persistent model storage, heavy training jobs, permanent SQLite history |

> [!NOTE]
> On Vercel Serverless Functions (AWS Lambda), the filesystem is read-only (except `/tmp`, which is ephemeral and resets during cold starts). Live Scapy packet sniffing is disabled in serverless cloud sandboxes (use **Simulation Mode**).

---

## Option A: Direct Deployment on Vercel (All-in-One)

### Step 1: Push changes to GitHub
Ensure your repository on GitHub contains `vercel.json`, `api/index.py`, and root `requirements.txt`:
```bash
git add .
git commit -m "Configure Vercel serverless deployment"
git push origin main
```

### Step 2: Import into Vercel
1. Go to [vercel.com](https://vercel.com) and log in with your GitHub account.
2. Click **"Add New..."** > **"Project"**.
3. Locate `Ai-based-smart-defence-network-` and click **Import**.
4. Configure Project Settings:
   - **Framework Preset**: Select **Other**.
   - **Root Directory**: `./` (leave default root).
   - **Build Command**: Leave blank.
   - **Output Directory**: Leave blank.
5. *(Optional)* Under **Environment Variables**, add:
   - `SMART_DEFENCE_SECRET`: A secure 32+ character hex string for session hashing.
6. Click **Deploy**.

Vercel will deploy the static assets to the global edge network and build the Python API under `@vercel/python`.

---

## Option B: Vercel (Frontend) + Render / Railway (Backend) — *Recommended*

If you want long-running model training (>15s) and permanent SQLite databases that persist forever without resetting on cold starts:

### Step 1: Deploy Backend to Render (Free)
1. Go to [render.com](https://render.com) and click **New Web Service**.
2. Connect your GitHub repository.
3. Configure settings:
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements-tested.txt`
   - **Start Command**: `gunicorn -w 2 -b 0.0.0.0:$PORT "app:create_app()"` (or `python app.py`)
4. Copy your backend URL (e.g., `https://smart-defence-api.onrender.com`).

### Step 2: Point Vercel to Your Backend
In `vercel.json`, update the `/api/` rewrite rule to proxy requests directly to your backend:
```json
{
  "version": 2,
  "rewrites": [
    {
      "source": "/api/(.*)",
      "destination": "https://smart-defence-api.onrender.com/api/$1"
    },
    {
      "source": "/assets/(.*)",
      "destination": "/frontend/$1"
    },
    {
      "source": "/favicon.ico",
      "destination": "/frontend/favicon.ico"
    },
    {
      "source": "/",
      "destination": "/frontend/index.html"
    },
    {
      "source": "/(.*)",
      "destination": "/frontend/$1"
    }
  ]
}
```
Commit and push. Vercel automatically proxies all `/api/*` traffic to your persistent backend with zero CORS issues!

---

## Deploying via Vercel CLI (Optional)

If you have Node.js installed on your machine, you can also deploy directly from the command line:

```bash
# Run Vercel CLI via npx (no global install needed)
npx vercel

# Deploy to production
npx vercel --prod
```
