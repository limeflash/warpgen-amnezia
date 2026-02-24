# WarpGen — WARP Generator for AmneziaWG 2.0

Web UI to generate Cloudflare WARP configs for AmneziaWG 2.0.

## Quick Deploy

### 1. Clone / copy files to your server

```bash
scp -r ./warpgen-web user@your-server:/opt/warpgen
```

### 2. Start with Docker

```bash
cd /opt/warpgen
docker compose up -d
```

App runs on port **3000** by default.

### 3. Nginx reverse proxy (for warpgen.simg.pro)

```nginx
server {
    listen 80;
    server_name warpgen.simg.pro;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name warpgen.simg.pro;

    # SSL (certbot / acme.sh)
    ssl_certificate     /etc/letsencrypt/live/warpgen.simg.pro/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/warpgen.simg.pro/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
    }
}
```

```bash
# Issue certificate (certbot)
certbot --nginx -d warpgen.simg.pro

# Reload nginx
nginx -s reload
```

### Update

```bash
cd /opt/warpgen
docker compose down
docker compose up -d --build
```

## Project Structure

```
warpgen-web/
├── server.js          # Node.js/Express backend
├── package.json
├── Dockerfile
├── docker-compose.yml
└── public/
    └── index.html     # UI
```

## Environment Variables

| Variable | Default | Description        |
|----------|---------|--------------------|
| `PORT`   | `3000`  | HTTP port to bind  |
