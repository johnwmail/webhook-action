# webhook-action

A small self-hosted GitHub webhook receiver written in Go. It verifies incoming
webhook deliveries with HMAC-SHA256, maps every JSON field of the payload onto
`DEPLOY_PARAM_*` environment variables, and then asynchronously runs your deploy
script.

No external dependencies — just the Go standard library.

## How it works

1. GitHub sends a webhook `POST` to `/action/webhook`.
2. The listener validates the `X-Hub-Signature-256` header against
   `WEBHOOK_SECRET`. Requests with a missing or wrong signature are rejected.
3. The JSON payload is parsed dynamically and each key is injected into the
   deploy script's environment as `DEPLOY_PARAM_<UPPERCASED_KEY>`.

   For example, a payload like:

   ```json
   {
     "ref": "refs/tags/v1.2.3",
     "tag": "v1.2.3",
     "actor": "octocat"
   }
   ```

   becomes `DEPLOY_PARAM_REF`, `DEPLOY_PARAM_TAG`, and
   `DEPLOY_PARAM_ACTOR` for the script.
4. The deploy script runs asynchronously so the webhook returns immediately.

## Configuration

The server is configured entirely through environment variables:

| Variable             | Required | Default           | Description                                    |
| -------------------- | -------- | ----------------- | ---------------------------------------------- |
| `WEBHOOK_SECRET`     | yes      | —                 | The webhook secret used to verify signatures.  |
| `DEPLOY_SCRIPT_PATH` | yes      | —                 | Absolute path to the script executed on deploy.|
| `LISTEN_ADDR`        | no       | `127.0.0.1:9000`  | Address the HTTP server binds to.              |

Generate a secret with:

```sh
openssl rand -hex 32
```

## Build & test

```sh
go build -o webhook-action .
go test -race ./...
```

## Run

```sh
WEBHOOK_SECRET=$(openssl rand -hex 32) \
DEPLOY_SCRIPT_PATH=/path/to/deploy.sh \
./webhook-action
```

The listener logs its endpoint on startup:

```
動態 Webhook 伺服器已啟動，監聽於 http://127.0.0.1:9000/action/webhook
```

Point the server at the URL your GitHub webhook payloads are sent to:

```
http://<host>:9000/action/webhook
```

Content type should be `application/json`.

## GitHub webhook setup

1. Go to your repository **Settings → Webhooks → Add webhook**.
2. Set the **Payload URL** to your server's `/action/webhook` endpoint.
3. Set **Content type** to `application/json`.
4. Paste the same `openssl rand -hex 32` secret into the **Secret** field.
5. Choose the events you want to trigger deploys (custom events work because the
   payload is parsed dynamically).

## Test it with curl

The webhook only accepts requests carrying a valid `X-Hub-Signature-256` header,
so compute the signature from the exact body you are about to send:

```sh
SECRET="$(cat ~/.config/webhook-action/webhook-action.env | grep WEBHOOK_SECRET | cut -d= -f2)"
BODY='{"ref":"refs/tags/v1.2.3","tag":"v1.2.3","actor":"octocat"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

curl -i -X POST "http://127.0.0.1:9000/action/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
```

If a valid signature is supplied, the server replies `200` immediately with
`Deployment triggered successfully with dynamic params.` while the deploy script
runs in the background.

A few negative cases to check:

```sh
# 401 — header missing
curl -i -X POST "http://127.0.0.1:9000/action/webhook" \
  -H "Content-Type: application/json" -d '{"tag":"v1.2.3"}'

# 403 — wrong signature
curl -i -X POST "http://127.0.0.1:9000/action/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$(printf x | openssl dgst -sha256 -hmac wrong | awk '{print $2}')" \
  -d '{"tag":"v1.2.3"}'

# 400 — invalid JSON
BODY='{"tag": "v1.2.3"'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"
curl -i -X POST "http://127.0.0.1:9000/action/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
```

## Deployment

The repo ships a ready-to-use systemd *user* unit and an example env file under
[`deploy/`](deploy/):

```sh
install -Dm 0644 deploy/webhook-action.service ~/.config/systemd/user/webhook-action.service
install -Dm 0644 deploy/webhook-action.env     ~/.config/webhook-action/webhook-action.env
systemctl --user daemon-reload
systemctl --user enable --now webhook-action
```

Start at boot and keep running after logout:

```sh
loginctl enable-linger "$USER"
```

Check status and logs:

```sh
systemctl --user status webhook-action
journalctl --user -u webhook-action -f
```

The service binds to localhost only, so place it behind a reverse proxy
(nginx/caddy) that terminates TLS on remote hosts. See
[`deploy/webhook-action.service`](deploy/webhook-action.service) for a template.

On every valid delivery, the payload fields are injected into the script
environment as `DEPLOY_PARAM_*` variables. An example script lives at
[`deploy/deploy.sh`](deploy/deploy.sh).

## Security notes

- The signature check uses `crypto/subtle`-style constant-time comparison
  (`hmac.Equal`) to avoid timing attacks.
- Keep `WEBHOOK_SECRET` a high-entropy random string and never commit it.
- The script path and listen address are controlled by the operator via
  environment variables, never by webhook payloads.
- Bind to localhost (the default) and only expose the endpoint through a
  TLS-terminating reverse proxy.

## License

[GPL-3.0](LICENSE)