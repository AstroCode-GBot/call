# Security checklist

- Dashboard uses a required environment-supplied password, CSRF tokens, secure session settings on HTTPS, strict upload extension/content probing, and size/duration limits.
- The voice webhook validates Twilio's request signature and only serves inbound call instructions; no outgoing-call endpoint exists.
- Media URLs are HMAC-signed and expire.
- Keep storage buckets private and restrict object-store credentials to the necessary bucket.
- Do not commit `.env` files or provider tokens.
- On Render Free, local disk is temporary. Configure persistent storage if uploads must survive restarts/deploys.
