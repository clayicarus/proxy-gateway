FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags "-s -w" -o /proxy-gateway ./cmd/gateway

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /proxy-gateway /usr/local/bin/proxy-gateway

EXPOSE 8443/udp 8443/tcp 9090/tcp 9091/tcp

ENTRYPOINT ["proxy-gateway"]
CMD ["-c", "/etc/proxy-gateway/gateway.yaml"]
