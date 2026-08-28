# The Vörður gateway: an OpenAI-compatible proxy that runs the checks itself.
#
#   docker build -t vordur/gateway .
#   docker run -p 8080:8080 -e VORDUR_UPSTREAM=https://api.openai.com/v1 vordur/gateway
#
# Then point a client at it and change nothing else:
#   OpenAI(base_url="http://localhost:8080/v1")   # Authorization passes through
#
# The image installs the library and nothing more. The gateway's HTTP shell is
# standard library only, so there is no web framework to pull in, and the base
# install has three dependencies.
FROM python:3.12-slim

# Run as a non-root user. A proxy on the egress path is a target, and it needs
# no privilege it is not given.
RUN useradd --create-home --uid 10001 vordur

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# --no-cache-dir keeps the layer small; the gateway needs the base install plus
# the optional yaml extra so VORDUR_POLICY can point at a file.
RUN pip install --no-cache-dir '.[yaml]'

USER vordur

ENV VORDUR_HOST=0.0.0.0 \
    VORDUR_PORT=8080 \
    VORDUR_UPSTREAM=https://api.openai.com/v1

EXPOSE 8080

# A container orchestrator reads this; the gateway answers /healthz with the
# live session count.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:%s/healthz' % os.environ.get('VORDUR_PORT','8080'); \
sys.exit(0 if urllib.request.urlopen(url, timeout=2).status==200 else 1)"

ENTRYPOINT ["python", "-m", "vordur.gateway"]
