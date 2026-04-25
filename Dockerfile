FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /hy2-gateway ./cmd/gateway

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /hy2-gateway /usr/local/bin/hy2-gateway

EXPOSE 443/udp
EXPOSE 9090/tcp

ENTRYPOINT ["hy2-gateway"]
CMD ["-c", "/etc/hy2-gateway/gateway.yaml"]
