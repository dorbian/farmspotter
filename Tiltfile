APP_NAME = "honse-bootstrap-viewer"
IMAGE_REF = APP_NAME + ":tilt"
CONTAINER_NAME = APP_NAME + "-dev"
CONTAINER_PORT = 8080
HOST_PORT = 8080
BOOTSTRAP_DNS_NAME = "hay.honse.farm"
REFRESH_INTERVAL = "60"
# Change this to "docker" if that's your runtime.
CONTAINER_CLI = "podman"

watch_files = [
    "Dockerfile",
    "requirements.txt",
    "main.py",
    "templates",
    "Tiltfile",
]

local_resource(
    "viewer-image",
    "%s build -t %s ." % (CONTAINER_CLI, IMAGE_REF),
    deps=watch_files,
    labels=["build"],
)

serve_script = """
set -euo pipefail
{cli} rm -f {name} >/dev/null 2>&1 || true
trap "{cli} rm -f {name} >/dev/null 2>&1 || true" EXIT
{cli} run --rm --name {name} \
  -p {host}:{container} \
  -e BOOTSTRAP_DNS_NAME={dns} \
  -e REFRESH_INTERVAL={refresh} \
  -e BIND_HOST=0.0.0.0 \
  -e BIND_PORT={container} \
  {image}
""".format(
    cli=CONTAINER_CLI,
    name=CONTAINER_NAME,
    host=HOST_PORT,
    container=CONTAINER_PORT,
    dns=BOOTSTRAP_DNS_NAME,
    refresh=REFRESH_INTERVAL,
    image=IMAGE_REF,
)

local_resource(
    "viewer-app",
    cmd="true",
    serve_cmd="bash -c '%s'" % serve_script,
    resource_deps=["viewer-image"],
    labels=["runtime"],
)
