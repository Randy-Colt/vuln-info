FROM golang:1.27-alpine AS build

RUN apk add --no-cache gcc musl-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/threat_info \
    ./cmd/threat_info/main.go

FROM alpine:3.20

RUN apk add --no-cache tzdata \
 && addgroup -S app \
 && adduser  -S app -G app \
 && mkdir -p /data /app/certs \
 && chown -R app:app /app

WORKDIR /app

COPY --from=build /out/threat_info .

USER app

EXPOSE 8000

VOLUME ["/app/data"]

ENTRYPOINT ["/app/threat_info"]