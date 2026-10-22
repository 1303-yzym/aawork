# syntax=docker/dockerfile:1

FROM golang:1.24.2-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mdns-go ./cmd/mdns-go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 survey
COPY --from=build /out/mdns-go /usr/local/bin/mdns-go
USER survey
ENTRYPOINT ["/usr/local/bin/mdns-go"]
CMD ["-h"]
