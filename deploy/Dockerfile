# Multi-stage build: static binary (CGO disabled) into a distroless base.
# VPP is reached purely over the binary API unix socket, so no C deps are needed.

FROM golang:1.25 AS builder
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
      -X github.com/kawaiinetworks/flowspec-vpp-agent/internal/version.Version=${VERSION} \
      -X github.com/kawaiinetworks/flowspec-vpp-agent/internal/version.Commit=${COMMIT} \
      -X github.com/kawaiinetworks/flowspec-vpp-agent/internal/version.Date=${DATE}" \
    -o /flowspec-vpp-agent ./cmd/flowspec-vpp-agent

FROM gcr.io/distroless/static-debian12
COPY --from=builder /flowspec-vpp-agent /flowspec-vpp-agent
# Default user is root (uid 0): the agent must open the root-owned
# /run/vpp/api.sock, and orchestrators that cannot override the container user
# (e.g. VyOS `set container`) rely on the image already running as root.
EXPOSE 10179
ENTRYPOINT ["/flowspec-vpp-agent"]
CMD ["--config", "/etc/flowspec-vpp-agent/config.yaml"]
