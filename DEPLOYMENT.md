# Netlify Deployment Guide for PhishGuard AI

## Prerequisites
- Netlify account
- Git repository (GitHub, GitLab, or Bitbucket)
- Python 3.9+ installed locally

## Step 1: Push to Git Repository
```bash
git add .
git commit -m "Add Netlify deployment configuration"
git push origin main
```

## Step 2: Set Up Netlify Site
1. Go to [Netlify](https://app.netlify.com/)
2. Click "Add new site" → "Import an existing project"
3. Connect your Git provider
4. Select the `phishguard` repository
5. Set build settings:
   - **Base directory**: `phishguard`
   - **Build command**: `python manage.py collectstatic --noinput && python manage.py migrate`
   - **Publish directory**: `staticfiles`

## Step 3: Configure Environment Variables
In Netlify dashboard → Site settings → Environment variables, add:

```
DJANGO_SECRET_KEY=z-m+9s_xw_#@08^06dcr%wh@q)^r1km(nqei1_$v-_ta72tqo*
DJANGO_SETTINGS_MODULE=phishguard.settings_production
DEBUG=False
DATABASE_URL=sqlite:///db.sqlite3
```

## Step 4: Deploy
1. Click "Deploy site"
2. Netlify will automatically build and deploy your Django app

## Step 5: Post-Deployment Setup
1. Create superuser for admin access:
   - Enable Netlify Functions
   - Access the function endpoint to run createsuperuser command
2. Update ALLOWED_HOSTS in settings_production.py with your Netlify domain
3. Test all functionality including:
   - Dashboard at `https://yoursite.netlify.app/`
   - Admin panel at `https://yoursite.netlify.app/admin`
   - API endpoints at `https://yoursite.netlify.app/api/scan/`

## Important Notes
- The current setup uses SQLite for simplicity
- For production, consider using PostgreSQL via Netlify's database add-ons
- Static files are served via WhiteNoise
- API requests are handled through Netlify Functions
- The ML model files should be placed in the `ml/` directory before deployment

## Troubleshooting
- If build fails, check Python version compatibility
- For database issues, ensure migrations run correctly
- Static file issues may require manual collection
- API endpoints may need CORS configuration updates
