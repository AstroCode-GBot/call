from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(APP_DIR / "data"))).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
AUDIO_LIMIT_SECONDS = 120
VIDEO_LIMIT_SECONDS = 60
MEDIA_LINK_TTL_SECONDS = int(os.getenv("MEDIA_LINK_TTL_SECONDS", "21600"))  # 6 hours
ALLOWED_EXTENSIONS = {".mp3", ".wav", ".m4a", ".aac", ".ogg", ".flac", ".mp4", ".webm", ".mov"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL", "")).startswith("https://"),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)
# Render sits behind a trusted reverse proxy. This preserves HTTPS URLs for links.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL", "")).strip().rstrip("/")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
MEDIA_SIGNING_SECRET = os.getenv("MEDIA_SIGNING_SECRET", "")
TWILIO_WEBHOOK_URL = os.getenv("TWILIO_WEBHOOK_URL", "").strip()

# Optional S3-compatible object storage. Recommended for Render's free filesystem,
# which is ephemeral. If not configured, files are kept in DATA_DIR.
S3_BUCKET = os.getenv("S3_BUCKET", "").strip()
S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "").strip()
S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "").strip()
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "").strip() or None
S3_REGION = os.getenv("S3_REGION", "auto" if S3_ENDPOINT_URL else "us-east-1")
S3_PREFIX = os.getenv("S3_PREFIX", "media-voice").strip("/")
S3_ENABLED = bool(S3_BUCKET and S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY)
S3 = None
if S3_ENABLED:
    S3 = boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT_URL,
        region_name=S3_REGION,
        aws_access_key_id=S3_ACCESS_KEY_ID,
        aws_secret_access_key=S3_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4", s3={"addressing_style": "path"}),
    )

LOCAL_BLOB_DIR = DATA_DIR / "objects"
LOCAL_BLOB_DIR.mkdir(parents=True, exist_ok=True)
STATE_KEY = f"{S3_PREFIX}/state.json" if S3_ENABLED else None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def state_key() -> Path:
    return DATA_DIR / "state.json"


def load_state() -> dict[str, Any]:
    if S3_ENABLED:
        try:
            obj = S3.get_object(Bucket=S3_BUCKET, Key=STATE_KEY)
            state = json.loads(obj["Body"].read().decode("utf-8"))
            if isinstance(state, dict) and isinstance(state.get("media"), list):
                return state
        except Exception as exc:
            # A missing state object is normal for the first run. Do not mask
            # other storage errors if S3 is configured incorrectly.
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in {"NoSuchKey", "404", "NotFound"}:
                app.logger.exception("Could not read state from object storage")
                raise RuntimeError("Object storage could not read its state. Check S3 settings.") from exc
        return {"media": [], "active_media_id": None}

    path = state_key()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("media"), list):
            return data
    except FileNotFoundError:
        pass
    except Exception:
        app.logger.exception("Local media index is unreadable")
        raise RuntimeError("Media index is unreadable. Restore state.json or clear it deliberately.")
    return {"media": [], "active_media_id": None}


def save_state(state: dict[str, Any]) -> None:
    encoded = json.dumps(state, ensure_ascii=False, indent=2).encode("utf-8")
    if S3_ENABLED:
        S3.put_object(Bucket=S3_BUCKET, Key=STATE_KEY, Body=encoded, ContentType="application/json")
        return
    path = state_key()
    temp = path.with_suffix(".json.tmp")
    temp.write_bytes(encoded)
    os.replace(temp, path)


def blob_key(media_id: str, variant: str, extension: str | None = None) -> str:
    if variant == "audio":
        suffix = "playback.mp3"
    elif variant == "original":
        suffix = f"original{extension or '.bin'}"
    else:
        raise ValueError("Unknown media variant")
    return f"{S3_PREFIX}/media/{media_id}/{suffix}" if S3_ENABLED else f"media/{media_id}/{suffix}"


def save_blob(key: str, source: Path, content_type: str) -> None:
    if S3_ENABLED:
        S3.upload_file(str(source), S3_BUCKET, key, ExtraArgs={"ContentType": content_type})
        return
    destination = LOCAL_BLOB_DIR / key
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def read_blob(key: str) -> bytes:
    if S3_ENABLED:
        response = S3.get_object(Bucket=S3_BUCKET, Key=key)
        return response["Body"].read()
    path = LOCAL_BLOB_DIR / key
    # Protect against accidental path traversal, even though generated keys are trusted.
    try:
        path.resolve().relative_to(LOCAL_BLOB_DIR.resolve())
    except ValueError:
        abort(404)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        abort(404)


def delete_blob(key: str) -> None:
    if S3_ENABLED:
        S3.delete_object(Bucket=S3_BUCKET, Key=key)
        return
    path = LOCAL_BLOB_DIR / key
    try:
        path.resolve().relative_to(LOCAL_BLOB_DIR.resolve())
        path.unlink(missing_ok=True)
        if path.parent.exists():
            shutil.rmtree(path.parent, ignore_errors=True)
    except ValueError:
        app.logger.warning("Rejected path outside storage directory")


def get_media(media_id: str) -> dict[str, Any] | None:
    state = load_state()
    return next((item for item in state["media"] if item.get("id") == media_id), None)


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_template_values() -> dict[str, Any]:
    return {"csrf_token": csrf_token, "s3_enabled": S3_ENABLED}


def require_login() -> None:
    if not session.get("logged_in"):
        flash("Please sign in first.", "warning")
        abort(401)


def verify_csrf() -> None:
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="The form expired or its security token was invalid. Refresh and try again.")


def effective_public_base_url() -> str:
    """Resolve the public URL, using Render's host/request host as a safe fallback."""
    configured = PUBLIC_BASE_URL or os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
    if configured:
        return configured
    # ProxyFix above preserves the external HTTPS scheme on Render.
    try:
        return request.url_root.rstrip("/")
    except RuntimeError:
        return ""


def effective_media_signing_secret() -> str:
    """Use a dedicated signing secret when configured; otherwise reuse Flask's secret."""
    return MEDIA_SIGNING_SECRET or str(app.config["SECRET_KEY"])


def sign_asset(media_id: str, variant: str, expiry: int) -> str:
    secret = effective_media_signing_secret()
    payload = f"{media_id}:{variant}:{expiry}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return signature


def make_asset_url(media_id: str, variant: str) -> str:
    base_url = effective_public_base_url()
    if not base_url:
        raise RuntimeError("Public URL could not be determined. Set PUBLIC_BASE_URL in Render Environment.")
    expiry = int(time.time()) + MEDIA_LINK_TTL_SECONDS
    signature = sign_asset(media_id, variant, expiry)
    return f"{base_url}/asset/{media_id}/{variant}?exp={expiry}&sig={signature}"


def valid_asset_signature(media_id: str, variant: str, expiry_text: str, signature: str) -> bool:
    try:
        expiry = int(expiry_text)
    except (TypeError, ValueError):
        return False
    if expiry < int(time.time()) or expiry > int(time.time()) + MEDIA_LINK_TTL_SECONDS + 300:
        return False
    expected = sign_asset(media_id, variant, expiry)
    return bool(signature) and hmac.compare_digest(expected, signature)


def probe_media(path: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        data = json.loads(result.stdout)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise ValueError("This file could not be read as valid audio/video. Please try a standard MP3, WAV, or MP4 file.") from exc

    streams = data.get("streams", [])
    audio = any(item.get("codec_type") == "audio" for item in streams)
    video = any(item.get("codec_type") == "video" for item in streams)
    try:
        duration = float(data.get("format", {}).get("duration", 0))
    except (TypeError, ValueError):
        duration = 0
    if not audio or duration <= 0:
        raise ValueError("No playable audio track or duration was detected in this file.")
    return {"duration": duration, "has_audio": audio, "has_video": video}


def twilio_signature_valid() -> bool:
    """Validate Twilio's X-Twilio-Signature for a configured POST webhook URL."""
    if not TWILIO_AUTH_TOKEN:
        return False
    signature = request.headers.get("X-Twilio-Signature", "")
    if not signature:
        return False
    base_url = effective_public_base_url()
    url = TWILIO_WEBHOOK_URL or (f"{base_url}/voice" if base_url else "")
    if not url:
        return False
    # Twilio's documented signature algorithm: URL plus sorted parameter names
    # and their values, signed with HMAC-SHA1 and Base64-encoded.
    parts = [url]
    grouped: dict[str, list[str]] = {}
    for key, value in request.form.items(multi=True):
        grouped.setdefault(key, []).append(value)
    for key in sorted(grouped):
        parts.append(key)
        parts.extend(sorted(grouped[key]))
    digest = hmac.new(TWILIO_AUTH_TOKEN.encode("utf-8"), "".join(parts).encode("utf-8"), hashlib.sha1).digest()
    expected = base64.b64encode(digest).decode("ascii")
    return hmac.compare_digest(expected, signature)


def xml_response(play_url: str | None) -> str:
    # Escape XML text manually. URLs are generated by this application only.
    from xml.sax.saxutils import escape

    if play_url:
        body = f"<Play>{escape(play_url)}</Play>"
    else:
        body = "<Say>There is no audio selected yet. Please configure your media dashboard.</Say>"
    return f'<?xml version="1.0" encoding="UTF-8"?><Response>{body}<Hangup/></Response>'


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.get("/")
def index():
    if not session.get("logged_in"):
        return render_template("login.html")
    try:
        state = load_state()
    except RuntimeError as exc:
        flash(str(exc), "error")
        state = {"media": [], "active_media_id": None}
    items = sorted(state["media"], key=lambda item: item.get("uploaded_at", ""), reverse=True)
    active_id = state.get("active_media_id")
    return render_template("index.html", media_items=items, active_id=active_id, max_upload_mb=MAX_UPLOAD_MB, s3_enabled=S3_ENABLED)


@app.post("/login")
def login():
    verify_csrf()
    password = request.form.get("password", "")
    if not ADMIN_PASSWORD:
        flash("ADMIN_PASSWORD is not configured. Set it in Render → Environment.", "error")
        return redirect(url_for("index"))
    if not hmac.compare_digest(password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")):
        # Avoid revealing whether the username or password was wrong.
        flash("Incorrect password.", "error")
        return redirect(url_for("index"))
    session.clear()
    session["logged_in"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    flash("Welcome. Your media dashboard is ready.", "success")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    require_login()
    verify_csrf()
    session.clear()
    return redirect(url_for("index"))


@app.post("/upload")
def upload():
    require_login()
    verify_csrf()
    if "file" not in request.files or not request.files["file"].filename:
        flash("Choose an audio or video file first.", "error")
        return redirect(url_for("index"))

    uploaded = request.files["file"]
    safe_name = secure_filename(uploaded.filename) or "uploaded-media"
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        flash("Unsupported format. Use MP3, WAV, M4A, AAC, OGG, FLAC, MP4, WebM, or MOV.", "error")
        return redirect(url_for("index"))

    media_id = uuid.uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="media-voice-") as temp_dir:
            temp_root = Path(temp_dir)
            input_path = temp_root / f"input{extension}"
            audio_path = temp_root / "playback.mp3"
            uploaded.save(input_path)
            file_size = input_path.stat().st_size
            if file_size <= 0:
                raise ValueError("The selected file is empty.")
            if file_size > MAX_UPLOAD_BYTES:
                raise ValueError(f"File is too large. Maximum upload size is {MAX_UPLOAD_MB} MB.")

            probe = probe_media(input_path)
            is_video = extension in VIDEO_EXTENSIONS or probe["has_video"]
            duration = probe["duration"]
            max_duration = VIDEO_LIMIT_SECONDS if is_video else AUDIO_LIMIT_SECONDS
            if duration > max_duration:
                limit_label = "1 minute" if is_video else "2 minutes"
                raise ValueError(f"This {'video' if is_video else 'audio'} is too long. Maximum duration is {limit_label}.")
            if is_video and not probe["has_video"]:
                raise ValueError("That file does not contain a video stream.")

            conversion = subprocess.run(
                [
                    "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                    "-i", str(input_path), "-vn", "-ac", "1", "-ar", "24000",
                    "-b:a", "64k", "-f", "mp3", str(audio_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=90,
            )
            if not audio_path.exists() or audio_path.stat().st_size == 0:
                raise ValueError("The audio conversion produced an empty file. Try another file.")

            original_key = blob_key(media_id, "original", extension)
            audio_key = blob_key(media_id, "audio")
            original_mime = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
            save_blob(original_key, input_path, original_mime)
            save_blob(audio_key, audio_path, "audio/mpeg")

        state = load_state()
        record = {
            "id": media_id,
            "filename": safe_name[:160],
            "extension": extension,
            "kind": "video" if is_video else "audio",
            "duration": round(duration, 2),
            "size_bytes": file_size,
            "original_mime": original_mime,
            "original_key": original_key,
            "audio_key": audio_key,
            "uploaded_at": utc_now(),
        }
        state["media"] = [item for item in state["media"] if item.get("id") != media_id]
        state["media"].append(record)
        state["active_media_id"] = media_id
        save_state(state)
        flash("Upload complete. The full audio track is converted and selected for your inbound-call webhook.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    except subprocess.TimeoutExpired:
        flash("Media processing timed out. Try a smaller or shorter file.", "error")
    except Exception:
        app.logger.exception("Media upload failed")
        flash("Upload failed. Check the Render logs and storage configuration, then try again.", "error")
    return redirect(url_for("index"))


@app.post("/select/<media_id>")
def select_media(media_id: str):
    require_login()
    verify_csrf()
    state = load_state()
    if not any(item.get("id") == media_id for item in state["media"]):
        abort(404)
    state["active_media_id"] = media_id
    save_state(state)
    flash("Selected audio updated for future inbound calls.", "success")
    return redirect(url_for("index"))


@app.post("/delete/<media_id>")
def delete_media(media_id: str):
    require_login()
    verify_csrf()
    state = load_state()
    item = next((entry for entry in state["media"] if entry.get("id") == media_id), None)
    if item is None:
        abort(404)
    delete_blob(item["original_key"])
    delete_blob(item["audio_key"])
    state["media"] = [entry for entry in state["media"] if entry.get("id") != media_id]
    if state.get("active_media_id") == media_id:
        state["active_media_id"] = None
    save_state(state)
    flash("Media deleted.", "success")
    return redirect(url_for("index"))


@app.get("/preview/<media_id>")
def preview(media_id: str):
    require_login()
    try:
        item = get_media(media_id)
        if item is None:
            abort(404)
        source_url = make_asset_url(media_id, "original")
        audio_url = make_asset_url(media_id, "audio")
    except RuntimeError as exc:
        app.logger.exception("Preview could not be prepared because storage/configuration is unavailable")
        return render_template(
            "error.html",
            code=503,
            message=("Preview could not be prepared. Check Render Environment variables and Logs. "
                     "If you configured S3 storage, verify its bucket and credentials. "
                     f"Details: {exc}"),
        ), 503
    return render_template(
        "preview.html",
        item=item,
        source_url=source_url,
        audio_url=audio_url,
    )


@app.get("/asset/<media_id>/<variant>")
def asset(media_id: str, variant: str):
    if variant not in {"original", "audio"}:
        abort(404)
    expiry = request.args.get("exp", "")
    signature = request.args.get("sig", "")
    if not valid_asset_signature(media_id, variant, expiry, signature):
        abort(403)
    item = get_media(media_id)
    if item is None:
        abort(404)
    key = item["original_key"] if variant == "original" else item["audio_key"]
    mime = item["original_mime"] if variant == "original" else "audio/mpeg"
    filename = item["filename"] if variant == "original" else f"{Path(item['filename']).stem}.mp3"
    data = read_blob(key)
    # Enable HTTP byte-range responses so browser audio/video players can seek and
    # progressively load media instead of showing a blank player on some clients.
    response = send_file(
        io.BytesIO(data),
        mimetype=mime,
        as_attachment=False,
        download_name=filename,
        conditional=True,
        etag=False,
        max_age=0,
    )
    response.headers["Content-Disposition"] = f'inline; filename="{secure_filename(filename) or "media"}"'
    response.headers["Accept-Ranges"] = "bytes"
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/voice", methods=["POST"])
def voice():
    # This endpoint only serves inbound calls to a number configured in your own
    # provider account. It does not place outbound calls or target arbitrary numbers.
    if not TWILIO_AUTH_TOKEN:
        return "Set TWILIO_AUTH_TOKEN in the Render environment first.", 503
    if not effective_public_base_url():
        return "Set PUBLIC_BASE_URL in the Render environment first.", 503
    if not twilio_signature_valid():
        app.logger.warning("Rejected a voice webhook with an invalid signature")
        return "Forbidden", 403

    try:
        state = load_state()
        active_id = state.get("active_media_id")
        active = next((item for item in state["media"] if item.get("id") == active_id), None)
        playback_url = make_asset_url(active_id, "audio") if active else None
        return app.response_class(xml_response(playback_url), mimetype="application/xml")
    except Exception:
        app.logger.exception("Could not produce voice webhook response")
        return "Voice service is temporarily unavailable.", 503


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "storage": "s3-compatible" if S3_ENABLED else "local-ephemeral-or-mounted-disk",
        "ffmpeg_available": shutil.which("ffmpeg") is not None,
        "ffprobe_available": shutil.which("ffprobe") is not None,
        "public_url_configured": bool(PUBLIC_BASE_URL or os.getenv("RENDER_EXTERNAL_URL")),
        "dedicated_media_signing_secret_configured": bool(MEDIA_SIGNING_SECRET),
        "twilio_auth_token_configured": bool(TWILIO_AUTH_TOKEN),
    })


@app.errorhandler(401)
def unauthenticated(_error):
    if request.path.startswith("/asset/") or request.path == "/voice":
        return "Unauthorized", 401
    flash("Please sign in to continue.", "warning")
    return redirect(url_for("index"))


@app.errorhandler(403)
def forbidden(error):
    if request.path.startswith("/asset/") or request.path == "/voice":
        return "Forbidden", 403
    return render_template("error.html", code=403, message=getattr(error, "description", "Forbidden")), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="That page or media item was not found."), 404


@app.errorhandler(413)
def too_large(_error):
    message = f"Request too large. Maximum file size is {MAX_UPLOAD_MB} MB."
    if session.get("logged_in"):
        flash(message, "error")
        return redirect(url_for("index"))
    return message, 413


@app.errorhandler(400)
def bad_request(error):
    if session.get("logged_in"):
        return render_template("error.html", code=400, message=getattr(error, "description", "Bad request")), 400
    return getattr(error, "description", "Bad request"), 400


@app.errorhandler(500)
def internal_server_error(error):
    # Keep secrets and tracebacks out of the page; the full details remain in Render Logs.
    original = getattr(error, "original_exception", None)
    if original is not None:
        app.logger.error(
            "Unhandled application error (%s)", type(original).__name__,
            exc_info=(type(original), original, original.__traceback__),
        )
    else:
        app.logger.error("Unhandled application error: %s", error)
    return render_template(
        "error.html",
        code=500,
        message="The server hit an unexpected error. Check Render → Logs for the traceback. "
                "For preview issues, verify PUBLIC_BASE_URL, SECRET_KEY, MEDIA_SIGNING_SECRET, "
                "and your media storage configuration.",
    ), 500


if __name__ == "__main__":
    # Only for local development. Render uses Gunicorn via Dockerfile.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
