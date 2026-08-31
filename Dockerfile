# WarpEP by ArJey - zero-dependency image, ~50 MB.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="WarpEP by ArJey" \
      org.opencontainers.image.description="Real Cloudflare WARP endpoint scanner" \
      org.opencontainers.image.source="https://github.com/arjeyproject/WarpEP" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY warpep ./warpep
COPY pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir . && adduser -D -u 10001 warpep
USER warpep

ENTRYPOINT ["warpep"]
CMD ["scan", "--fast"]
