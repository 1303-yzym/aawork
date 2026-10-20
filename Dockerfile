# syntax=docker/dockerfile:1

FROM golang:1.24.2-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aawork .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 survey
COPY --from=build /out/aawork /usr/local/bin/aawork
USER survey
ENTRYPOINT ["/usr/local/bin/aawork"]
CMD ["-h"]
