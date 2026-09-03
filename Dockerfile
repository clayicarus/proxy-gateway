FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /proxy-gateway ./cmd/gateway

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /proxy-gateway /usr/local/bin/proxy-gateway

EXPOSE 443/udp
EXPOSE 9090/tcp

ENTRYPOINT ["proxy-gateway"]
CMD ["-c", "/etc/proxy-gateway/gateway.yaml"]
