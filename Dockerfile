# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /bin/egress ./cmd/egress

# Runtime image
FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S openwaf && adduser -S openwaf -G openwaf

WORKDIR /app

COPY --from=builder /bin/egress /usr/local/bin/egress
COPY config.example.json /app/config.json

USER openwaf

EXPOSE 8070

ENTRYPOINT ["/usr/local/bin/egress"]
CMD ["-config", "/app/config.json"]
