# Find

PIN-protected live location sharing with OwnTracks, FastAPI, SQLite, Mapbox, and Cloudflare Tunnel.

## What It Does

- Receives live location updates from OwnTracks over HTTP.
- Serves a viewer page protected by 4-digit PINs.
- Serves an admin console protected by an admin password.
- Lets you create temporary PINs with notes, expiration, and device limits.
- Supports direct share links such as `https://find.example.com/?pin=1234`.
- Includes an installable admin PWA for quick access on mobile.

## Stack

- Python 3.12
- FastAPI + Uvicorn
- SQLite
- Docker Compose
- Mapbox GL JS
- Cloudflare Tunnel

## Repository Layout

- `app/main.py`: application server, API routes, embedded HTML, and icon generation.
- `app/requirements.txt`: Python dependencies.
- `docker-compose.yml`: app + Cloudflare Tunnel deployment.
- `.env.example`: template for local secrets and deployment settings.

## Setup

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit `.env` with your real values.
3. Start the stack:

```bash
docker compose up -d --build
```

4. Point your Cloudflare Tunnel hostname at `http://find:8000`.

## Important Environment Variables

- `PUBLIC_BASE`: public viewer/admin URL, for example `https://find.example.com`.
- `APP_BIND_IP`: IP address Docker should bind to on the host. For direct OwnTracks over Tailscale, use the Pi's Tailscale IP.
- `APP_PORT`: host port for the FastAPI container.
- `VIEWER_LABEL`: text shown in the viewer HUD, for example `Antonin Beliard`.
- `MAPBOX_PUBLIC_TOKEN`: Mapbox public token used by the viewer.
- `MAPBOX_STYLE_URL`: Mapbox style URL for the viewer map.
- `ADMIN_PASSWORD`: admin login password.
- `ADMIN_SESSION_SECRET`: random secret used to sign admin sessions.
- `OT_USER`: OwnTracks HTTP basic auth username.
- `OT_PASS`: OwnTracks HTTP basic auth password.
- `OWNTRACKS_ENFORCE_IP`: when set to `1`, the ingest endpoint only accepts requests from `OWNTRACKS_ALLOWED_CIDRS`.
- `CLOUDFLARE_TUNNEL_TOKEN`: Cloudflare Tunnel token for the `cloudflared` container.

## OwnTracks Configuration

Use `HTTP` mode, not MQTT.

- URL: `http://<APP_BIND_IP>:<APP_PORT>/api/owntracks`
- If OwnTracks asks for split fields:
  - Host: value of `APP_BIND_IP`
  - Port: value of `APP_PORT`
  - Path: `/api/owntracks`
- TLS: off
- WebSockets: off
- Authentication: on
- Username: value of `OT_USER`
- Password: value of `OT_PASS`
- Secret encryption key: empty / disabled

Notes:

- If `OWNTRACKS_ENFORCE_IP=1`, send updates over Tailscale or another allowed network, not through the public hostname.
- The app does not route by OwnTracks `User ID` or `Device ID`; those can be whatever you want.
- If you enable OwnTracks payload encryption, this server will reject the request.

## Admin Console

- Visit `/admin`.
- Sign in with `ADMIN_PASSWORD`.
- Create 4-digit PINs with:
  - `Note`
  - `Hours`
  - `Max devices`
- Use `Share` to generate a direct viewer link with the PIN already in the URL.
- Device limits are counted per browser/device cookie, not per tab.

## Viewer

- The viewer auto-opens when someone visits a valid `?pin=` link.
- The same `?pin=` value stays in the URL, so refresh keeps the viewer open while the PIN is still valid.
- The map uses Mapbox GL JS with a light 2D style.

## Data And Security Notes

- Runtime data is stored in the Docker volume mounted at `/data/find.sqlite`.
- Keep `.env` private. It contains your passwords, tokens, and deployment-specific values.
- This repository is configured to ignore `.env`, SQLite files, Python cache files, and local Codex metadata.
- For a public deployment, use a strong `ADMIN_PASSWORD` and a separate random `ADMIN_SESSION_SECRET`.

## Development

Run the syntax check used during deployment:

```bash
python3 - <<'PY'
from pathlib import Path
compile(Path('app/main.py').read_text(), 'app/main.py', 'exec')
print('ok')
PY
```
