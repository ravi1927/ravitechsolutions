# Deploy Ravi Tech Solutions on DigitalOcean

1. Buy a domain (example: ravitechsolutions.com) and point the A record to the droplet IP.
2. Upload this folder to the web root. Update `sitemap.xml` and `robots.txt` to that domain.
3. Copy `.env.example` to `.env` on the server only.
4. Put your private inbox in `MAIL_TO`. For Gmail SMTP use an App Password in `SMTP_USER` / `SMTP_PASS`.
5. Set `SITE_URL` and a long `STATS_KEY`. Bookmark `/stats.html?key=...` for visitor reports.
6. `chmod 600 .env` and `chmod 700 data`. Enable Apache `rewrite`, `headers`, `ssl`. Use Certbot for HTTPS.
