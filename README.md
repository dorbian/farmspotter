# HonseFarm Federation Viewer

This container:
1) Reads the TXT record for `BOOTSTRAP_DNS_NAME` (default: `hay.honse.farm`)
2) Extracts `https://...` URL(s) from the TXT record
3) Converts them to `.../api/federation/servers/summary`
4) Fetches the JSON list of servers
5) Visualizes it in a small web UI

## Run with Podman

```bash
podman build -t honse-bootstrap-viewer .
podman run --rm -p 8080:8080 honse-bootstrap-viewer
```

Open: http://localhost:8080

## Run with Tilt (live reload)

Tilt can watch the source tree, rebuild the container image, and relaunch it automatically.

1. Install [Tilt](https://tilt.dev).
2. From this directory, run:

```bash
tilt up
```

When prompted, press `space` to open the Tilt UI (or browse to http://localhost:10350) and tail the logs.

### Customizing the dev run

- Change settings at runtime via flags, e.g. `tilt up -- --bootstrap_dns_name=hay.honse.farm --refresh_interval=120`.
- Override the exposed port with `--host_port=18080`.
- Set `CONTAINER_CLI=podman` before running `tilt up` if you prefer Podman over Docker.

Stop the stack with `tilt down` (or `Ctrl+C` from the terminal that is running Tilt).

## Environment variables

- `BOOTSTRAP_DNS_NAME` (default: `hay.honse.farm`)
- `REFRESH_INTERVAL` (default: `300`)
- `DNS_SERVERS` optional: comma-separated resolver IPs, e.g. `1.1.1.1,8.8.8.8`
- `BOOTSTRAP_URLS` optional: comma-separated bootstrap base URLs (skips TXT), e.g. `https://bootstrap-beta.honse.farm`
- `BIND_PORT` (default: `8080`)
