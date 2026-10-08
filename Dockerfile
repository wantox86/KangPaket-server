FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kangpaket-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=builder /out/kangpaket-server /usr/local/bin/kangpaket-server
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kangpaket-server"]
