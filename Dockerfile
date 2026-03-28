FROM golang:1.25 AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o soquery-server ./cmd/soquery-server/

FROM gcr.io/distroless/static-debian12

COPY --from=builder /build/soquery-server /usr/local/bin/soquery-server

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/soquery-server"]
