import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import struct
import time
import zlib
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


DEBUG = _env_bool("DEBUG", False)
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "").rstrip("/")
VIEWER_LABEL = (os.environ.get("VIEWER_LABEL", "Live location") or "Live location").strip()
DB_PATH = os.environ.get("DB_PATH", "/data/find.sqlite")
MAPBOX_PUBLIC_TOKEN = os.environ.get("MAPBOX_PUBLIC_TOKEN", "")
MAPBOX_STYLE_URL = os.environ.get("MAPBOX_STYLE_URL", "mapbox://styles/mapbox/light-v11")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
LEGACY_ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_SESSION_SECRET = (
    os.environ.get("ADMIN_SESSION_SECRET")
    or LEGACY_ADMIN_TOKEN
    or ADMIN_PASSWORD
    or secrets.token_urlsafe(32)
)
ADMIN_SESSION_TTL_SECONDS = int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", "43200"))

OT_USER = os.environ.get("OT_USER", "")
OT_PASS = os.environ.get("OT_PASS", "")

OWNTRACKS_ENFORCE_IP = _env_bool("OWNTRACKS_ENFORCE_IP", False)
OWNTRACKS_ALLOWED_CIDRS = os.environ.get(
    "OWNTRACKS_ALLOWED_CIDRS",
    "100.64.0.0/10,127.0.0.1/32,::1/128" if OWNTRACKS_ENFORCE_IP else "",
).strip()

MAIN_DEVICE_ID = "main"
VIEWER_DEVICE_COOKIE = "find_device_id"
ADMIN_SESSION_COOKIE = "find_admin_session"
VIEWER_TOKEN_TTL_SECONDS = int(os.environ.get("VIEWER_TOKEN_TTL_SECONDS", "600"))
DEVICE_COOKIE_MAX_AGE_SECONDS = int(os.environ.get("DEVICE_COOKIE_MAX_AGE_SECONDS", "31536000"))
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
ADMIN_ASSET_VERSION = "20260411d"

app = FastAPI()

viewer_tokens: Dict[str, tuple[str, str, int]] = {}
watchers: Dict[str, set[WebSocket]] = {}
admin_icon_cache: Dict[int, bytes] = {}
browser_icon_cache: Dict[int, bytes] = {}


def _now() -> int:
    return int(time.time())


def _debug(*parts: object) -> None:
    if DEBUG:
        print(*parts, flush=True)


def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            _debug("Ignoring invalid CIDR in OWNTRACKS_ALLOWED_CIDRS:", repr(part))
    return nets


OWNTRACKS_ALLOWED_NETS = _parse_cidrs(OWNTRACKS_ALLOWED_CIDRS)


def _ip_allowed(ip_str: str) -> bool:
    if not OWNTRACKS_ALLOWED_NETS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in OWNTRACKS_ALLOWED_NETS)


def _request_is_secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return proto.split(",")[0].strip().lower() == "https"


def _effective_base(request: Request) -> str:
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    if host:
        return f"{proto}://{host}".rstrip("/")
    if PUBLIC_BASE:
        return PUBLIC_BASE
    return str(request.base_url).rstrip("/")


def _ensure_db_dir() -> None:
    parent = os.path.dirname(DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack("!I", len(data))
        + tag
        + data
        + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def _admin_icon_png(size: int) -> bytes:
    if size in admin_icon_cache:
        return admin_icon_cache[size]

    size = max(64, min(size, 1024))
    bg_top = (250, 247, 242)
    bg_bottom = (241, 236, 229)
    accent = (36, 92, 65)
    white = (255, 255, 255)
    scale = size / 56.0
    outer_radius = 15.0
    inner_radius = 6.4
    center = 28.0
    samples = ((0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75))
    if size >= 256:
        samples = ((0.5, 0.5),)

    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            red = 0
            green_sum = 0
            blue = 0
            for sx, sy in samples:
                px = (x + sx) / scale
                py = (y + sy) / scale
                ratio = min(1.0, max(0.0, py / 56.0))
                color = (
                    round(bg_top[0] + (bg_bottom[0] - bg_top[0]) * ratio),
                    round(bg_top[1] + (bg_bottom[1] - bg_top[1]) * ratio),
                    round(bg_top[2] + (bg_bottom[2] - bg_top[2]) * ratio),
                )

                dx = px - center
                dy = py - center
                if dx * dx + dy * dy <= outer_radius * outer_radius:
                    color = accent
                if dx * dx + dy * dy <= inner_radius * inner_radius:
                    color = white

                red += color[0]
                green_sum += color[1]
                blue += color[2]

            rows.extend((red // len(samples), green_sum // len(samples), blue // len(samples), 255))

    ihdr = struct.pack("!IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + _png_chunk(b"IEND", b"")
    )
    admin_icon_cache[size] = png
    return png


def _browser_icon_png(size: int) -> bytes:
    if size in browser_icon_cache:
        return browser_icon_cache[size]

    size = max(16, min(size, 256))
    accent = (36, 92, 65)
    scale = size / 56.0
    outer_radius = 20.5
    inner_radius = 9.25
    center = 28.0
    samples = ((0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75))

    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            red = 0
            green_sum = 0
            blue = 0
            alpha_sum = 0
            for sx, sy in samples:
                px = (x + sx) / scale
                py = (y + sy) / scale
                dx = px - center
                dy = py - center
                color = (0, 0, 0)
                alpha = 0

                if dx * dx + dy * dy <= outer_radius * outer_radius:
                    color = accent
                    alpha = 255
                if dx * dx + dy * dy <= inner_radius * inner_radius:
                    color = (0, 0, 0)
                    alpha = 0

                red += color[0]
                green_sum += color[1]
                blue += color[2]
                alpha_sum += alpha

            rows.extend(
                (
                    red // len(samples),
                    green_sum // len(samples),
                    blue // len(samples),
                    alpha_sum // len(samples),
                )
            )

    ihdr = struct.pack("!IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + _png_chunk(b"IEND", b"")
    )
    browser_icon_cache[size] = png
    return png


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return bool(row)


def _table_columns(conn: sqlite3.Connection, table: str) -> Dict[str, Dict[str, Any]]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    cols: Dict[str, Dict[str, Any]] = {}
    for cid, name, typ, notnull, dflt, pk in rows:
        cols[name] = {"type": typ, "notnull": bool(notnull), "pk": bool(pk), "dflt": dflt}
    return cols


def _pick_column(cols: Dict[str, Dict[str, Any]], preferred: list[str], contains: list[str]) -> Optional[str]:
    for candidate in preferred:
        if candidate in cols:
            return candidate
    for candidate in cols:
        lowered = candidate.lower()
        if any(part in lowered for part in contains):
            return candidate
    return None


def _ensure_latest_schema(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "latest"):
        conn.execute(
            """
            CREATE TABLE latest(
              device_id TEXT PRIMARY KEY,
              payload TEXT NOT NULL,
              updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        return

    cols = _table_columns(conn, "latest")
    if "device_id" in cols and "payload" in cols and "updated_at" in cols:
        return

    payload_col = _pick_column(cols, preferred=["payload"], contains=["payload", "json", "body"])
    updated_col = _pick_column(cols, preferred=["updated_at"], contains=["updated", "time", "ts", "tst"])

    old_payload = None
    old_updated = _now()
    if payload_col:
        try:
            if updated_col:
                row = conn.execute(
                    f"SELECT {payload_col}, {updated_col} FROM latest ORDER BY {updated_col} DESC LIMIT 1"
                ).fetchone()
            else:
                row = conn.execute(f"SELECT {payload_col} FROM latest LIMIT 1").fetchone()
            if row:
                old_payload = row[0]
                if len(row) > 1 and row[1] is not None:
                    old_updated = int(row[1])
        except Exception as exc:
            _debug("Failed to read previous latest row:", repr(exc))

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS latest_new(
          device_id TEXT PRIMARY KEY,
          payload TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
        """
    )
    if old_payload is not None:
        conn.execute(
            "INSERT OR REPLACE INTO latest_new(device_id, payload, updated_at) VALUES(?,?,?)",
            (MAIN_DEVICE_ID, str(old_payload), old_updated),
        )
    conn.execute("DROP TABLE latest")
    conn.execute("ALTER TABLE latest_new RENAME TO latest")
    conn.commit()


def _ensure_codes_schema(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "codes"):
        conn.execute(
            """
            CREATE TABLE codes(
              code TEXT PRIMARY KEY,
              label TEXT,
              expires_at INTEGER NOT NULL,
              max_viewers INTEGER,
              created_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        return

    cols = _table_columns(conn, "codes")
    if "label" not in cols:
        conn.execute("ALTER TABLE codes ADD COLUMN label TEXT")
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE codes ADD COLUMN expires_at INTEGER")
    if "max_viewers" not in cols:
        conn.execute("ALTER TABLE codes ADD COLUMN max_viewers INTEGER")
    if "created_at" not in cols:
        conn.execute("ALTER TABLE codes ADD COLUMN created_at INTEGER")

    cols = _table_columns(conn, "codes")
    default_expiry = _now() + 365 * 24 * 3600
    default_created = _now()
    if "device_id" in cols:
        conn.execute("UPDATE codes SET label = COALESCE(label, device_id)")
    else:
        conn.execute("UPDATE codes SET label = COALESCE(label, 'Share')")
    conn.execute("UPDATE codes SET expires_at = COALESCE(expires_at, ?)", (default_expiry,))
    conn.execute("UPDATE codes SET created_at = COALESCE(created_at, ?)", (default_created,))
    conn.commit()


def _ensure_code_devices_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS code_devices(
          code TEXT NOT NULL,
          device_id TEXT NOT NULL,
          first_seen_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          PRIMARY KEY(code, device_id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_code_devices_code ON code_devices(code)")
    conn.commit()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    _ensure_latest_schema(conn)
    _ensure_codes_schema(conn)
    _ensure_code_devices_schema(conn)


def db() -> sqlite3.Connection:
    _ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _purge_expired_state(conn: sqlite3.Connection) -> None:
    now = _now()
    conn.execute("DELETE FROM codes WHERE expires_at <= ?", (now,))
    conn.execute("DELETE FROM code_devices WHERE code NOT IN (SELECT code FROM codes)")
    conn.commit()


def _purge_viewer_tokens() -> None:
    now = _now()
    expired = [token for token, (_, _, exp) in viewer_tokens.items() if exp <= now]
    for token in expired:
        viewer_tokens.pop(token, None)


def parse_basic_auth(request: Request) -> Optional[tuple[str, str]]:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        username, password = raw.split(":", 1)
        return username, password
    except Exception:
        return None


def _safe_json_loads(raw: str) -> Optional[dict]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _payload_tst_seconds(payload: dict) -> int:
    try:
        tst = int(payload.get("tst") or 0)
        if tst > 0:
            return tst
    except Exception:
        pass
    return _now()


def _has_coordinates(payload: dict) -> bool:
    try:
        float(payload["lat"])
        float(payload["lon"])
        return True
    except Exception:
        return False


def _extract_location_payloads(obj: Any) -> list[dict]:
    if isinstance(obj, dict):
        return [obj] if obj.get("_type") == "location" and _has_coordinates(obj) else []
    if isinstance(obj, list):
        out: list[dict] = []
        for item in obj:
            if isinstance(item, dict) and item.get("_type") == "location" and _has_coordinates(item):
                out.append(item)
        return out
    return []


def get_latest_main() -> Optional[dict]:
    try:
        with db() as conn:
            row = conn.execute("SELECT payload FROM latest WHERE device_id=?", (MAIN_DEVICE_ID,)).fetchone()
        if not row:
            return None
        return _safe_json_loads(row["payload"])
    except sqlite3.OperationalError as exc:
        _debug("get_latest_main OperationalError:", repr(exc))
        return None


def get_latest_meta() -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT payload, updated_at FROM latest WHERE device_id=?",
            (MAIN_DEVICE_ID,),
        ).fetchone()
    if not row:
        return None
    payload = _safe_json_loads(row["payload"])
    if not payload:
        return None
    return {
        "payload": payload,
        "updated_at": int(row["updated_at"]),
    }


def _sign_admin_value(raw: str) -> str:
    return hmac.new(
        ADMIN_SESSION_SECRET.encode("utf-8"),
        raw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _new_admin_session_cookie() -> str:
    expires_at = _now() + ADMIN_SESSION_TTL_SECONDS
    payload = str(expires_at)
    return f"{payload}.{_sign_admin_value(payload)}"


def _valid_admin_session(cookie_value: str) -> bool:
    if not cookie_value or "." not in cookie_value:
        return False
    payload, signature = cookie_value.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign_admin_value(payload)):
        return False
    try:
        return int(payload) > _now()
    except ValueError:
        return False


def _admin_password_configured() -> bool:
    return bool(ADMIN_PASSWORD or LEGACY_ADMIN_TOKEN)


def _admin_password_matches(candidate: str) -> bool:
    options = [value for value in (ADMIN_PASSWORD, LEGACY_ADMIN_TOKEN) if value]
    return any(secrets.compare_digest(candidate, value) for value in options)


def _has_legacy_admin_token(request: Request) -> bool:
    if not LEGACY_ADMIN_TOKEN:
        return False
    query_token = request.query_params.get("token", "")
    if query_token and secrets.compare_digest(query_token, LEGACY_ADMIN_TOKEN):
        return True
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        bearer = auth.split(" ", 1)[1].strip()
        if secrets.compare_digest(bearer, LEGACY_ADMIN_TOKEN):
            return True
    return False


def require_admin(request: Request) -> None:
    if _valid_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE, "")):
        return
    if _has_legacy_admin_token(request):
        return
    raise HTTPException(status_code=401, detail="Unauthorized")


def _viewer_device_id(request: Request) -> tuple[str, bool]:
    cookie_value = request.cookies.get(VIEWER_DEVICE_COOKIE, "")
    if DEVICE_ID_RE.fullmatch(cookie_value):
        return cookie_value, False
    return secrets.token_urlsafe(24), True


def _set_cookie(
    response: JSONResponse,
    request: Request,
    name: str,
    value: str,
    *,
    max_age: int,
    httponly: bool,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        secure=_request_is_secure(request),
        httponly=httponly,
        samesite="lax",
        path="/",
    )


def _clear_cookie(response: JSONResponse, name: str) -> None:
    response.delete_cookie(key=name, path="/", samesite="lax")


def _track_code_device(conn: sqlite3.Connection, code: str, device_id: str, max_devices: Optional[int]) -> int:
    now = _now()
    existing = conn.execute(
        "SELECT 1 FROM code_devices WHERE code=? AND device_id=?",
        (code, device_id),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE code_devices SET last_seen_at=? WHERE code=? AND device_id=?",
            (now, code, device_id),
        )
        count_row = conn.execute("SELECT COUNT(*) AS count FROM code_devices WHERE code=?", (code,)).fetchone()
        return int(count_row["count"])

    count_row = conn.execute("SELECT COUNT(*) AS count FROM code_devices WHERE code=?", (code,)).fetchone()
    used_devices = int(count_row["count"])
    if max_devices is not None and used_devices >= int(max_devices):
        raise HTTPException(403, detail="Code has reached its device limit")

    conn.execute(
        "INSERT INTO code_devices(code, device_id, first_seen_at, last_seen_at) VALUES(?,?,?,?)",
        (code, device_id, now, now),
    )
    return used_devices + 1


def viewer_html() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Find</title>
  <meta name="theme-color" content="#f5f1ea" />
  <link rel="icon" type="image/png" sizes="32x32" href="/browser-icon-32.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="icon" type="image/png" sizes="64x64" href="/browser-icon-64.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="shortcut icon" href="/favicon.ico?v=__ADMIN_ASSET_VERSION__">
  <link rel="apple-touch-icon" sizes="180x180" href="/admin-icon-180.png?v=__ADMIN_ASSET_VERSION__">
  <link href="https://api.mapbox.com/mapbox-gl-js/v3.19.1/mapbox-gl.css" rel="stylesheet">
  <style>
    :root{
      color-scheme:light;
      --bg:#f5f1ea;
      --card:rgba(255,255,255,.92);
      --line:rgba(17,24,39,.1);
      --text:#111827;
      --muted:#6b7280;
      --accent:#245c41;
      --shadow:0 24px 80px rgba(17,24,39,.12);
    }
    html,body,#map{height:100%;margin:0}
    body{background:linear-gradient(180deg,#faf7f2 0%,#f1ece5 100%);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    #map{background:#ece7df}
    #overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(245,241,234,.64);backdrop-filter:blur(18px);z-index:30}
    #card{width:min(360px,92vw);background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:28px;padding:24px;box-shadow:var(--shadow)}
    h1{font-size:24px;margin:0 0 18px;font-weight:650;letter-spacing:-.03em}
    #row{display:flex;gap:10px}
    input{flex:1;font-size:18px;padding:14px 16px;border-radius:16px;border:1px solid var(--line);background:#fff;color:var(--text);outline:none;box-shadow:inset 0 1px 1px rgba(17,24,39,.04)}
    input::placeholder{color:#9ca3af}
    button{font-size:16px;padding:14px 18px;border-radius:16px;border:0;background:#111827;color:white;cursor:pointer}
    button[disabled]{opacity:.65;cursor:wait}
    #err{color:#b42318;margin-top:10px;min-height:18px;font-size:14px}
    #hud{position:fixed;left:18px;top:18px;z-index:20;background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:22px;padding:14px 16px;min-width:220px;max-width:min(320px,calc(100vw - 36px));display:none;box-shadow:var(--shadow)}
    #status{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
    #status:empty{display:none}
    #meta{font-size:15px;line-height:1.45}
    #status:not(:empty) + #meta{margin-top:6px}
    .location-marker{position:relative;width:48px;height:66px}
    .marker-pulse{position:absolute;left:50%;bottom:2px;width:18px;height:18px;background:rgba(36,92,65,.16);border-radius:999px;transform:translateX(-50%);animation:pulse 2.2s ease-out infinite}
    .marker-pin{position:absolute;left:50%;top:0;width:42px;height:56px;transform:translateX(-50%);filter:drop-shadow(0 16px 28px rgba(36,92,65,.24))}
    .marker-pin svg{display:block;width:100%;height:100%}
    .mapboxgl-ctrl-bottom-right{right:12px;bottom:12px}
    .mapboxgl-ctrl-group{border-radius:14px !important;overflow:hidden;box-shadow:0 10px 24px rgba(17,24,39,.12) !important}
    .mapboxgl-ctrl-group button{border-radius:0 !important}
    @keyframes pulse{
      0%{transform:translateX(-50%) scale(.85);opacity:.8}
      70%{transform:translateX(-50%) scale(2.5);opacity:0}
      100%{transform:translateX(-50%) scale(2.5);opacity:0}
    }
    @media (max-width: 720px){
      #hud{left:12px;top:12px;right:auto;min-width:0;max-width:min(280px,calc(100vw - 24px));padding:12px 14px;border-radius:18px}
      #status{font-size:11px}
      #meta{font-size:14px}
      #card{width:min(360px,calc(100vw - 24px));padding:18px;border-radius:22px}
      #row{flex-direction:column}
      button{width:100%}
      .location-marker{width:42px;height:60px}
      .marker-pin{width:36px;height:50px}
    }
  </style>
</head>
<body>
  <div id="overlay">
    <div id="card">
      <h1>Enter PIN</h1>
      <div id="row">
        <input id="code" inputmode="numeric" maxlength="4" placeholder="1234" />
        <button id="go">Open</button>
      </div>
      <div id="err"></div>
    </div>
  </div>

  <div id="map"></div>
  <div id="hud">
    <div id="status">Waiting</div>
    <div id="meta"></div>
  </div>

  <script src="https://api.mapbox.com/mapbox-gl-js/v3.19.1/mapbox-gl.js"></script>
  <script>
    const MAPBOX_TOKEN = __MAPBOX_TOKEN__;
    const MAPBOX_STYLE = __MAPBOX_STYLE__;
    const DEFAULT_LABEL = __VIEWER_LABEL__;
    const overlay = document.getElementById('overlay');
    const codeEl = document.getElementById('code');
    const go = document.getElementById('go');
    const err = document.getElementById('err');
    const hud = document.getElementById('hud');
    const statusEl = document.getElementById('status');
    const metaEl = document.getElementById('meta');
    const params = new URLSearchParams(window.location.search);
    const urlPin = (params.get('pin') || '').trim();

    let map;
    let marker;
    let ws;
    let mapReady = false;
    let pendingLocation = null;
    let hasAutoSubmitted = false;

    function setStatus(text = DEFAULT_LABEL, meta = '') {
      hud.style.display = 'block';
      statusEl.textContent = text || DEFAULT_LABEL;
      metaEl.textContent = meta;
    }

    function circleFeature(lat, lon, radiusMeters) {
      const earthRadius = 6378137;
      const latRad = lat * Math.PI / 180;
      const coords = [];
      for (let i = 0; i <= 64; i += 1) {
        const angle = (i / 64) * Math.PI * 2;
        const dx = Math.cos(angle) * radiusMeters;
        const dy = Math.sin(angle) * radiusMeters;
        const pointLat = lat + (dy / earthRadius) * (180 / Math.PI);
        const pointLon = lon + (dx / (earthRadius * Math.cos(latRad))) * (180 / Math.PI);
        coords.push([pointLon, pointLat]);
      }
      return {
        type: 'Feature',
        geometry: {
          type: 'Polygon',
          coordinates: [coords],
        },
      };
    }

    function ensureMarker() {
      if (marker || !map) return;
      const el = document.createElement('div');
      el.className = 'location-marker';
      el.innerHTML = `
        <div class="marker-pulse"></div>
        <div class="marker-pin">
          <svg viewBox="0 0 42 56" aria-hidden="true">
            <path d="M21 55C21 55 4 33.7 4 21C4 11.61 11.61 4 21 4C30.39 4 38 11.61 38 21C38 33.7 21 55 21 55Z" fill="#245c41" stroke="white" stroke-width="3"/>
            <circle cx="21" cy="21" r="7" fill="white"/>
          </svg>
        </div>
      `;
      marker = new mapboxgl.Marker({ element: el, anchor: 'bottom' })
        .setLngLat([2.3522, 48.8566])
        .addTo(map);
    }

    function initMap() {
      if (map) return;
      if (!MAPBOX_TOKEN) {
        err.textContent = 'Mapbox token missing.';
        return;
      }
      mapboxgl.accessToken = MAPBOX_TOKEN;
      map = new mapboxgl.Map({
        container: 'map',
        style: MAPBOX_STYLE,
        center: [2.3522, 48.8566],
        zoom: 4.5,
        pitch: 0,
        bearing: 0,
        dragRotate: false,
        pitchWithRotate: false,
        maxPitch: 0,
        attributionControl: true,
      });
      map.touchZoomRotate.disableRotation();
      map.addControl(new mapboxgl.NavigationControl({ showCompass: false }), 'bottom-right');
      map.on('load', () => {
        mapReady = true;
        map.addSource('accuracy', {
          type: 'geojson',
          data: { type: 'FeatureCollection', features: [] },
        });
        map.addLayer({
          id: 'accuracy-fill',
          type: 'fill',
          source: 'accuracy',
          paint: {
            'fill-color': '#111827',
            'fill-opacity': 0.08,
          },
        });
        map.addLayer({
          id: 'accuracy-outline',
          type: 'line',
          source: 'accuracy',
          paint: {
            'line-color': '#111827',
            'line-opacity': 0.18,
            'line-width': 2,
          },
        });
        ensureMarker();
        if (pendingLocation) renderLocation(pendingLocation);
      });
    }

    function renderLocation(location) {
      const lat = Number(location.lat);
      const lon = Number(location.lon);
      const acc = Number(location.acc || 20);
      const tst = Number(location.tst || 0);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
        setStatus(DEFAULT_LABEL, 'Invalid location payload');
        return;
      }
      pendingLocation = location;
      initMap();
      if (!mapReady) return;
      ensureMarker();
      marker.setLngLat([lon, lat]);
      const accuracy = Math.max(5, acc || 20);
      map.getSource('accuracy').setData({
        type: 'FeatureCollection',
        features: [circleFeature(lat, lon, accuracy)],
      });
      const targetZoom = accuracy <= 30 ? 15.8 : accuracy <= 120 ? 14.4 : 13;
      map.easeTo({
        center: [lon, lat],
        zoom: targetZoom,
        duration: 900,
        essential: true,
      });
      const when = tst ? new Date(tst * 1000).toLocaleString() : 'unknown';
      const accuracyText = Number.isFinite(acc) ? ' ±' + Math.round(acc) + 'm' : '';
      setStatus(DEFAULT_LABEL, when + accuracyText);
    }

    async function login(code) {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({ code }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || body.error || 'Login failed');
      return body;
    }

    function connect(wsUrl) {
      if (ws) ws.close();
      initMap();
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setStatus(DEFAULT_LABEL, '');
      ws.onerror = () => setStatus(DEFAULT_LABEL, 'WebSocket error');
      ws.onclose = (event) => {
        if (event.code === 4401) {
          setStatus(DEFAULT_LABEL, 'Session expired. Enter the PIN again.');
          overlay.style.display = 'flex';
          return;
        }
        setStatus(DEFAULT_LABEL, 'Connection closed');
      };
      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'location') {
          renderLocation(msg.location);
          return;
        }
        if (msg.type === 'status') {
          setStatus(DEFAULT_LABEL, msg.message || '');
          return;
        }
        if (msg.type === 'error') {
          setStatus(DEFAULT_LABEL, msg.error || 'Error');
        }
      };
    }

    function submit() {
      err.textContent = '';
      const code = (codeEl.value || '').trim();
      if (!/^\\d{4}$/.test(code)) {
        err.textContent = 'Please enter 4 digits.';
        return;
      }
      history.replaceState(null, '', '/?pin=' + encodeURIComponent(code));
      go.disabled = true;
      login(code)
        .then(({ wsUrl }) => {
          overlay.style.display = 'none';
          connect(wsUrl);
        })
        .catch((e) => {
          err.textContent = e.message || String(e);
        })
        .finally(() => {
          go.disabled = false;
        });
    }

    go.addEventListener('click', submit);
    codeEl.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') submit();
    });

    if (/^\\d{4}$/.test(urlPin) && !hasAutoSubmitted) {
      hasAutoSubmitted = true;
      codeEl.value = urlPin;
      submit();
    }
  </script>
</body>
</html>
""".replace("__MAPBOX_TOKEN__", json.dumps(MAPBOX_PUBLIC_TOKEN)).replace("__MAPBOX_STYLE__", json.dumps(MAPBOX_STYLE_URL)).replace("__ADMIN_ASSET_VERSION__", ADMIN_ASSET_VERSION).replace("__VIEWER_LABEL__", json.dumps(VIEWER_LABEL))


def admin_login_html() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Find Admin</title>
  <meta name="theme-color" content="#f5f1ea" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="default" />
  <meta name="apple-mobile-web-app-title" content="Find Admin" />
  <link rel="icon" type="image/png" sizes="32x32" href="/browser-icon-32.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="icon" type="image/png" sizes="64x64" href="/browser-icon-64.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="shortcut icon" href="/favicon.ico?v=__ADMIN_ASSET_VERSION__">
  <link rel="manifest" href="/admin.webmanifest?v=__ADMIN_ASSET_VERSION__">
  <link rel="apple-touch-icon" sizes="180x180" href="/admin-icon-180.png?v=__ADMIN_ASSET_VERSION__">
  <style>
    :root{color-scheme:light}
    body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f1ea;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111827}
    .card{width:min(360px,92vw);background:rgba(255,255,255,.92);border:1px solid rgba(17,24,39,.1);border-radius:28px;padding:24px;box-shadow:0 24px 80px rgba(17,24,39,.08)}
    h1{margin:0 0 16px;font-size:24px;font-weight:650;letter-spacing:-.03em}
    form{display:flex;flex-direction:column;gap:12px}
    input{width:100%;box-sizing:border-box;padding:14px 16px;border-radius:16px;border:1px solid rgba(17,24,39,.1);background:#fff;color:#111827;font-size:16px}
    button{width:100%;padding:14px;border:0;border-radius:16px;background:#111827;color:white;font-size:16px;cursor:pointer}
    #err{min-height:18px;color:#b42318;margin-top:10px;font-size:14px}
  </style>
</head>
<body>
  <div class="card">
    <h1>Admin</h1>
    <form id="form">
      <input id="password" type="password" autocomplete="current-password" placeholder="Admin password" />
      <button type="submit">Sign in</button>
    </form>
    <div id="err"></div>
  </div>
  <script>
    const form = document.getElementById('form');
    const password = document.getElementById('password');
    const err = document.getElementById('err');

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      err.textContent = '';
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({ password: password.value }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        err.textContent = body.detail || body.error || 'Login failed';
        return;
      }
      window.location = '/admin';
    });
  </script>
</body>
</html>
""".replace("__ADMIN_ASSET_VERSION__", ADMIN_ASSET_VERSION)


def admin_html() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Find Admin</title>
  <meta name="theme-color" content="#f5f1ea" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="default" />
  <meta name="apple-mobile-web-app-title" content="Find Admin" />
  <link rel="icon" type="image/png" sizes="32x32" href="/browser-icon-32.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="icon" type="image/png" sizes="64x64" href="/browser-icon-64.png?v=__ADMIN_ASSET_VERSION__">
  <link rel="shortcut icon" href="/favicon.ico?v=__ADMIN_ASSET_VERSION__">
  <link rel="manifest" href="/admin.webmanifest?v=__ADMIN_ASSET_VERSION__">
  <link rel="apple-touch-icon" sizes="180x180" href="/admin-icon-180.png?v=__ADMIN_ASSET_VERSION__">
  <style>
    :root{
      color-scheme:light;
      --bg:#f5f1ea;
      --card:rgba(255,255,255,.9);
      --line:rgba(17,24,39,.1);
      --text:#111827;
      --muted:#6b7280;
      --shadow:0 24px 80px rgba(17,24,39,.08);
    }
    html{min-height:100%;background:linear-gradient(180deg,#faf7f2 0%,#f1ece5 100%)}
    body{min-height:100vh;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:linear-gradient(180deg,#faf7f2 0%,#f1ece5 100%);color:var(--text)}
    main{padding:24px;max-width:960px;margin:0 auto}
    .card{border:1px solid var(--line);border-radius:26px;padding:18px 18px 12px;background:var(--card);margin-bottom:16px;box-shadow:var(--shadow);backdrop-filter:blur(10px)}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between}
    .group{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .statusRow{display:flex;gap:12px;align-items:center;justify-content:space-between}
    .statusActions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;min-width:240px}
    .createForm{display:grid;grid-template-columns:minmax(0,1fr) 108px 148px auto;gap:10px;align-items:center;margin-bottom:10px}
    .muted{color:var(--muted)}
    h3{margin:0 0 14px;font-size:18px;font-weight:650;letter-spacing:-.02em}
    input{background:#fff;color:var(--text);border:1px solid var(--line);border-radius:16px;padding:12px 14px}
    button{background:#111827;color:white;border:0;border-radius:16px;padding:12px 14px;cursor:pointer}
    button.secondary{background:#fff;color:var(--text);border:1px solid var(--line)}
    .createForm input{width:100%;min-width:0;box-sizing:border-box}
    .createForm button{white-space:nowrap}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid var(--line);padding:12px 10px;text-align:left;font-size:14px;vertical-align:middle}
    code{background:#f3f4f6;padding:3px 7px;border-radius:999px}
    #err{color:#b42318;font-size:14px}
    #createOut,#shareOut{font-size:14px}
    #err:empty,#createOut:empty,#shareOut:empty{display:none}
    .actions{display:flex;gap:8px;justify-content:flex-end}
    @media (max-width: 720px) {
      table, thead, tbody, th, td, tr { display: block; }
      thead { display: none; }
      body{font-size:17px}
      main{padding:14px}
      .card{padding:18px 18px 16px;border-radius:22px}
      h3{font-size:20px;margin-bottom:16px}
      .muted{font-size:15px;line-height:1.45}
      input,button{font-size:16px;padding:14px 16px}
      .statusRow{flex-direction:column;align-items:stretch}
      .statusActions{width:100%;min-width:0}
      .createForm{grid-template-columns:1fr 1fr}
      .createForm > :first-child{grid-column:1 / -1}
      .createForm > :last-child{grid-column:1 / -1}
      input, #create{width:100%;box-sizing:border-box}
      tr { border: 1px solid var(--line); border-radius: 18px; margin-bottom: 12px; padding: 14px; background:#fff; box-shadow:0 8px 20px rgba(17,24,39,.04); display:grid; grid-template-columns:1fr 1fr; gap:12px 14px; }
      td { border: 0; padding: 0; display:block; margin:0; font-size:15px; line-height:1.45; min-width:0; }
      td::before { content: attr(data-label); display:block; color: var(--muted); font-size: 12px; line-height: 1.2; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 6px; }
      td:last-child { grid-column:1 / -1; padding-top: 2px; }
      td:last-child::before { display:none; }
      td code { white-space: nowrap; }
      .actions{width:100%;justify-content:stretch}
      .actions button{flex:1}
    }
  </style>
</head>
<body>
  <main>
    <div class="card">
      <h3>Status</h3>
      <div class="statusRow">
        <div class="muted" id="statusText">Loading…</div>
        <div class="statusActions">
          <button class="secondary" id="clearLatest">Clear cache</button>
          <button class="secondary" id="logout">Log out</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Create PIN</h3>
      <div class="createForm">
        <input id="label" placeholder="Note">
        <input id="ttl" type="number" min="1" value="24" placeholder="Hours">
        <input id="maxDevices" type="number" min="1" placeholder="Max devices">
        <button id="create">Create</button>
      </div>
      <div id="createOut" class="muted"></div>
    </div>

    <div class="card">
      <h3>Active PINs</h3>
      <div id="err"></div>
      <div id="shareOut" class="muted" style="margin-bottom:10px"></div>
      <div id="emptyState" class="muted">Retrieving pins...</div>
      <table id="codesTable">
        <thead>
          <tr>
            <th>PIN</th>
            <th>Note</th>
            <th>Expires</th>
            <th>Devices</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </main>

  <script>
    const err = document.getElementById('err');
    const tbody = document.getElementById('tbody');
    const statusText = document.getElementById('statusText');
    const createOut = document.getElementById('createOut');
    const shareOut = document.getElementById('shareOut');
    const emptyState = document.getElementById('emptyState');
    const codesTable = document.getElementById('codesTable');
    const legacyToken = new URLSearchParams(window.location.search).get('token') || '';
    const isMobileShareClient =
      navigator.userAgentData?.mobile === true ||
      /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(navigator.userAgent);

    async function api(path, opts = {}) {
      const headers = Object.assign({}, opts.headers || {});
      if (legacyToken) headers.Authorization = 'Bearer ' + legacyToken;
      const response = await fetch(path, Object.assign({ credentials: 'same-origin', headers }, opts));
      const body = await response.json().catch(() => ({}));
      if (response.status === 401) {
        window.location = '/admin';
        throw new Error('Unauthorized');
      }
      if (!response.ok) throw new Error(body.detail || body.error || ('HTTP ' + response.status));
      return body;
    }

    function row(rec) {
      const tr = document.createElement('tr');
      const deviceLimit = rec.max_devices == null ? '∞' : rec.max_devices;
      const shareUrl = window.location.origin + '/?pin=' + encodeURIComponent(rec.code);
      tr.innerHTML = `
        <td data-label="PIN"><code>${rec.code}</code></td>
        <td data-label="Note">${rec.label || ''}</td>
        <td data-label="Expires">${new Date(rec.expires_at * 1000).toLocaleString()}</td>
        <td data-label="Devices">${rec.used_devices} / ${deviceLimit}</td>
        <td>
          <div class="actions">
            <button class="secondary" data-action="share">Share</button>
            <button class="secondary" data-action="delete">Delete</button>
          </div>
        </td>
      `;
      tr.querySelector('[data-action="delete"]').onclick = async () => {
        await api('/api/admin/codes/' + rec.code, { method: 'DELETE' });
        await refresh();
      };
      tr.querySelector('[data-action="share"]').onclick = async () => {
        try {
          if (navigator.share && isMobileShareClient) {
            await navigator.share({ title: 'Find', url: shareUrl });
            shareOut.textContent = 'Share link ready: ' + shareUrl;
          } else if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(shareUrl);
            shareOut.textContent = 'Copied: ' + shareUrl;
          } else {
            window.prompt('Copy this link', shareUrl);
            shareOut.textContent = shareUrl;
          }
        } catch (e) {
          if (String(e).includes('AbortError')) return;
          shareOut.textContent = shareUrl;
        }
      };
      return tr;
    }

    async function refresh() {
      err.textContent = '';
      shareOut.textContent = '';
      tbody.innerHTML = '';
      emptyState.textContent = 'Retrieving pins...';
      emptyState.style.display = 'block';
      codesTable.style.display = 'none';
      try {
        const list = await api('/api/admin/codes');
        if (!list.length) {
          emptyState.textContent = 'No active pins right now.';
          return;
        }
        emptyState.style.display = 'none';
        codesTable.style.display = 'table';
        list.forEach((rec) => tbody.appendChild(row(rec)));
      } catch (error) {
        emptyState.style.display = 'none';
        throw error;
      }
    }

    async function refreshStatus() {
      try {
        const status = await api('/api/admin/status');
        if (!status.has_location) {
          statusText.textContent = 'No location stored yet.';
          return;
        }
        const latest = new Date(status.latest_tst * 1000).toLocaleString();
        const stored = new Date(status.stored_at * 1000).toLocaleString();
        statusText.textContent = `Location ${latest} · stored ${stored}`;
      } catch (e) {
        statusText.textContent = e.message || String(e);
      }
    }

    document.getElementById('create').onclick = async () => {
      createOut.textContent = '';
      err.textContent = '';
      shareOut.textContent = '';
      const label = document.getElementById('label').value.trim();
      const ttlHours = Number(document.getElementById('ttl').value || 24);
      const maxDevicesRaw = document.getElementById('maxDevices').value.trim();
      const maxDevices = maxDevicesRaw ? Number(maxDevicesRaw) : null;
      const rec = await api('/api/admin/codes', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ label, ttl_hours: ttlHours, max_devices: maxDevices }),
      });
      createOut.textContent = 'Created PIN: ' + rec.code;
      document.getElementById('label').value = '';
      document.getElementById('maxDevices').value = '';
      await refresh();
    };

    document.getElementById('clearLatest').onclick = async () => {
      err.textContent = '';
      await api('/api/admin/clear-latest', { method: 'POST' });
      await refreshStatus();
    };

    document.getElementById('logout').onclick = async () => {
      await api('/api/admin/logout', { method: 'POST' });
      window.location = '/admin';
    };

    refresh().catch((e) => { err.textContent = e.message || String(e); });
    refreshStatus();
    setInterval(refreshStatus, 10000);
  </script>
</body>
</html>
""".replace("__ADMIN_ASSET_VERSION__", ADMIN_ASSET_VERSION)


@app.get("/", response_class=HTMLResponse)
def viewer() -> HTMLResponse:
    return HTMLResponse(viewer_html())


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request) -> HTMLResponse:
    if _valid_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE, "")) or _has_legacy_admin_token(request):
        return HTMLResponse(admin_html())
    return HTMLResponse(admin_login_html())


@app.get("/admin.webmanifest")
def admin_manifest() -> JSONResponse:
    return JSONResponse(
        {
            "name": "Find Admin",
            "short_name": "Find Admin",
            "start_url": "/admin",
            "scope": "/admin",
            "display": "standalone",
            "background_color": "#f5f1ea",
            "theme_color": "#f5f1ea",
            "icons": [
                {
                    "src": f"/admin-icon-180.png?v={ADMIN_ASSET_VERSION}",
                    "sizes": "180x180",
                    "type": "image/png",
                },
                {
                    "src": f"/admin-icon-192.png?v={ADMIN_ASSET_VERSION}",
                    "sizes": "192x192",
                    "type": "image/png",
                },
                {
                    "src": f"/admin-icon-512.png?v={ADMIN_ASSET_VERSION}",
                    "sizes": "512x512",
                    "type": "image/png",
                },
            ],
        }
    )


def _admin_icon_response(size: int) -> Response:
    return Response(
        content=_admin_icon_png(size),
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


def _browser_icon_response(size: int) -> Response:
    return Response(
        content=_browser_icon_png(size),
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/admin-icon-{size}.png")
def admin_icon(size: int) -> Response:
    if size not in {180, 192, 512}:
        raise HTTPException(404, detail="Icon not found")
    return _admin_icon_response(size)


@app.get("/browser-icon-{size}.png")
def browser_icon(size: int) -> Response:
    if size not in {32, 64}:
        raise HTTPException(404, detail="Icon not found")
    return _browser_icon_response(size)


@app.get("/apple-touch-icon.png")
def apple_touch_icon() -> Response:
    return _admin_icon_response(180)


@app.get("/apple-touch-icon-precomposed.png")
def apple_touch_icon_precomposed() -> Response:
    return _admin_icon_response(180)


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(
        content=_browser_icon_png(64),
        media_type="image/png",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    latest = get_latest_meta()
    return {
        "ok": True,
        "has_location": bool(latest),
    }


@app.post("/api/admin/login")
async def admin_login(request: Request) -> JSONResponse:
    if not _admin_password_configured():
        raise HTTPException(503, detail="ADMIN_PASSWORD is not configured")

    body = await request.json()
    password = str(body.get("password", ""))
    if not _admin_password_matches(password):
        raise HTTPException(401, detail="Invalid password")

    response = JSONResponse({"ok": True})
    _set_cookie(
        response,
        request,
        ADMIN_SESSION_COOKIE,
        _new_admin_session_cookie(),
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
    )
    return response


@app.post("/api/admin/logout")
def admin_logout(request: Request) -> JSONResponse:
    response = JSONResponse({"ok": True})
    _clear_cookie(response, ADMIN_SESSION_COOKIE)
    return response


@app.get("/api/admin/codes")
def list_codes(request: Request) -> list[dict[str, Any]]:
    require_admin(request)
    with db() as conn:
        _purge_expired_state(conn)
        rows = conn.execute(
            """
            SELECT
              c.code,
              COALESCE(c.label, '') AS label,
              c.expires_at,
              c.max_viewers,
              c.created_at,
              (
                SELECT COUNT(*)
                FROM code_devices d
                WHERE d.code = c.code
              ) AS used_devices
            FROM codes c
            ORDER BY c.created_at DESC
            """
        ).fetchall()
    return [
        {
            "code": row["code"],
            "label": row["label"],
            "expires_at": int(row["expires_at"]),
            "max_devices": None if row["max_viewers"] is None else int(row["max_viewers"]),
            "created_at": int(row["created_at"]),
            "used_devices": int(row["used_devices"]),
        }
        for row in rows
    ]


@app.post("/api/admin/codes")
async def create_code(request: Request) -> dict[str, Any]:
    require_admin(request)
    body = await request.json()

    label = str(body.get("label", "")).strip() or "Share"
    ttl_hours = int(body.get("ttl_hours", 24))
    raw_limit = body.get("max_devices", body.get("max_viewers"))
    max_devices = None if raw_limit in (None, "") else int(raw_limit)

    if ttl_hours <= 0:
        raise HTTPException(400, detail="ttl_hours must be positive")
    if max_devices is not None and max_devices <= 0:
        raise HTTPException(400, detail="max_devices must be positive")

    with db() as conn:
        _purge_expired_state(conn)
        cols = _table_columns(conn, "codes")
        created_at = _now()
        expires_at = created_at + ttl_hours * 3600

        for _ in range(50):
            code = f"{secrets.randbelow(10000):04d}"
            exists = conn.execute("SELECT 1 FROM codes WHERE code=?", (code,)).fetchone()
            if exists:
                continue

            if "device_id" in cols:
                conn.execute(
                    "INSERT INTO codes(code, device_id, label, expires_at, max_viewers, created_at) VALUES(?,?,?,?,?,?)",
                    (code, MAIN_DEVICE_ID, label, expires_at, max_devices, created_at),
                )
            else:
                conn.execute(
                    "INSERT INTO codes(code, label, expires_at, max_viewers, created_at) VALUES(?,?,?,?,?)",
                    (code, label, expires_at, max_devices, created_at),
                )
            conn.commit()
            return {
                "code": code,
                "label": label,
                "expires_at": expires_at,
                "max_devices": max_devices,
                "created_at": created_at,
                "used_devices": 0,
            }

    raise HTTPException(500, detail="Could not allocate code")


@app.delete("/api/admin/codes/{code}")
def delete_code(code: str, request: Request) -> dict[str, bool]:
    require_admin(request)
    if not re.fullmatch(r"\d{4}", code):
        raise HTTPException(400, detail="Invalid code")
    with db() as conn:
        conn.execute("DELETE FROM codes WHERE code=?", (code,))
        conn.execute("DELETE FROM code_devices WHERE code=?", (code,))
        conn.commit()
    return {"ok": True}


@app.get("/api/admin/status")
def admin_status(request: Request) -> dict[str, Any]:
    require_admin(request)
    latest = get_latest_meta()
    if not latest:
        return {"has_location": False}
    payload = latest["payload"]
    return {
        "has_location": True,
        "latest_tst": _payload_tst_seconds(payload),
        "stored_at": int(latest["updated_at"]),
    }


@app.post("/api/admin/clear-latest")
def admin_clear_latest(request: Request) -> dict[str, bool]:
    require_admin(request)
    with db() as conn:
        conn.execute("DELETE FROM latest WHERE device_id=?", (MAIN_DEVICE_ID,))
        conn.commit()
    return {"ok": True}


@app.post("/api/login")
async def login(request: Request) -> JSONResponse:
    body = await request.json()
    code = str(body.get("code", "")).strip()
    if not re.fullmatch(r"\d{4}", code):
        raise HTTPException(400, detail="Invalid code")

    device_id, is_new_cookie = _viewer_device_id(request)

    with db() as conn:
        _purge_expired_state(conn)
        row = conn.execute(
            "SELECT expires_at, max_viewers FROM codes WHERE code=?",
            (code,),
        ).fetchone()
        if not row:
            raise HTTPException(404, detail="Code not found")

        expires_at = int(row["expires_at"])
        if _now() >= expires_at:
            raise HTTPException(403, detail="Code expired")

        max_devices = None if row["max_viewers"] is None else int(row["max_viewers"])
        used_devices = _track_code_device(conn, code, device_id, max_devices)
        conn.commit()

    token = secrets.token_urlsafe(24)
    viewer_tokens[token] = (code, device_id, _now() + VIEWER_TOKEN_TTL_SECONDS)
    _purge_viewer_tokens()

    base = _effective_base(request)
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    response = JSONResponse(
        {
            "wsUrl": f"{ws_base}/ws?token={token}",
            "code": code,
            "expires_at": expires_at,
            "used_devices": used_devices,
            "max_devices": max_devices,
        }
    )
    if is_new_cookie:
        _set_cookie(
            response,
            request,
            VIEWER_DEVICE_COOKIE,
            device_id,
            max_age=DEVICE_COOKIE_MAX_AGE_SECONDS,
            httponly=True,
        )
    return response


@app.post("/api/owntracks")
async def owntracks_ingest(request: Request) -> JSONResponse:
    if OWNTRACKS_ENFORCE_IP:
        peer = request.client.host if request.client else ""
        if not _ip_allowed(peer):
            raise HTTPException(403, detail="Forbidden")

    auth = parse_basic_auth(request)
    if not auth or auth[0] != OT_USER or auth[1] != OT_PASS:
        raise HTTPException(401, detail="Unauthorized")

    raw = await request.body()
    if not raw:
        return JSONResponse({"ok": True, "stored": False})

    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        _debug("OwnTracks payload was not valid JSON")
        return JSONResponse({"ok": True, "stored": False})

    if isinstance(obj, dict) and obj.get("_type") == "encrypted":
        raise HTTPException(400, detail="OwnTracks payload is encrypted. Disable the secret encryption key in OwnTracks.")

    locations = _extract_location_payloads(obj)
    if not locations:
        payload_type = obj.get("_type") if isinstance(obj, dict) else type(obj).__name__
        _debug(f"Ignoring OwnTracks payload without location data. type={payload_type}")
        return JSONResponse({"ok": True, "stored": False})

    payload = max(locations, key=_payload_tst_seconds)
    incoming_tst = _payload_tst_seconds(payload)

    existing = get_latest_main()
    if existing and incoming_tst < _payload_tst_seconds(existing):
        _debug("Ignoring older location payload", incoming_tst, _payload_tst_seconds(existing))
        return JSONResponse({"ok": True, "stored": False})

    stored_at = _now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO latest(device_id, payload, updated_at) VALUES(?,?,?)
            ON CONFLICT(device_id) DO UPDATE SET
              payload=excluded.payload,
              updated_at=excluded.updated_at
            """,
            (MAIN_DEVICE_ID, json.dumps(payload), stored_at),
        )
        conn.commit()

    message = json.dumps({"type": "location", "location": payload})
    dead: list[tuple[str, WebSocket]] = []
    for code, sockets in watchers.items():
        for ws in list(sockets):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append((code, ws))
    for code, ws in dead:
        watchers.get(code, set()).discard(ws)

    _debug(
        "Accepted location",
        f"tst={incoming_tst}",
        f"lat={payload.get('lat')}",
        f"lon={payload.get('lon')}",
        f"acc={payload.get('acc')}",
    )
    return JSONResponse({"ok": True, "stored": True, "tst": incoming_tst})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    _purge_viewer_tokens()
    token = ws.query_params.get("token", "")
    record = viewer_tokens.get(token)
    if not record:
        await ws.close(code=4401)
        return

    code, _, exp = record
    if _now() >= exp:
        viewer_tokens.pop(token, None)
        await ws.close(code=4401)
        return

    with db() as conn:
        _purge_expired_state(conn)
        row = conn.execute("SELECT expires_at FROM codes WHERE code=?", (code,)).fetchone()

    if not row or _now() >= int(row["expires_at"]):
        await ws.accept()
        await ws.send_text(json.dumps({"type": "error", "error": "Code expired"}))
        await ws.close(code=4403)
        return

    await ws.accept()
    watchers.setdefault(code, set()).add(ws)

    latest = get_latest_main()
    if latest:
        await ws.send_text(json.dumps({"type": "location", "location": latest}))
    else:
        await ws.send_text(
            json.dumps(
                {
                    "type": "status",
                    "status": "Waiting",
                    "message": "No location received yet",
                }
            )
        )

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        watchers.get(code, set()).discard(ws)
