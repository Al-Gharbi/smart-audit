# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /smart-audit ./

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /smart-audit /smart-audit

ENTRYPOINT ["/smart-audit"]
CMD ["--help"]

# Usage:
#   docker run --rm -v $(pwd)/contracts:/data al-gharbi/smart-audit \
#       scan /data/ -r -f html -o /data/audit-report.html
