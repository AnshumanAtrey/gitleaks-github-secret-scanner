FROM apify/actor-python:3.13

# Install git + gitleaks (the scanner binary)
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks (pinned for reproducibility)
ARG GITLEAKS_VERSION=8.30.1
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) GL_ARCH="x64" ;; \
        arm64) GL_ARCH="arm64" ;; \
        *) echo "unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    gitleaks version

USER myuser

COPY --chown=myuser:myuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=myuser:myuser . ./

CMD ["python3", "-m", "src.main"]
