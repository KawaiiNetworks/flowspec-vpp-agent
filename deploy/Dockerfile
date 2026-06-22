# Multi-stage build: static binary (CGO disabled) into a distroless base.
# VPP is reached purely over the binary API unix socket, so no C deps are needed.

FROM golang:1.24 AS builder
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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /flowspec-vpp-agent /flowspec-vpp-agent
# Runs as root in deployment (see compose user: "0:0") to access /run/vpp/api.sock.
EXPOSE 10179 9469
ENTRYPOINT ["/flowspec-vpp-agent"]
CMD ["-config", "/etc/flowspec-vpp-agent/config.yaml"]
