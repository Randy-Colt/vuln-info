FROM golang:1.27-alpine AS build

RUN apk add --no-cache gcc musl-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/threat-info \
    ./cmd/threat-info

FROM alpine:3.20

RUN apk add --no-cache tzdata \
 && addgroup -S app \
 && adduser  -S app -G app

WORKDIR /data

COPY --from=build /out/threat-info /usr/local/bin/threat-info

RUN chown -R app:app /data

USER app

EXPOSE 8000

VOLUME ["/data"]

ENTRYPOINT ["threat-info"]