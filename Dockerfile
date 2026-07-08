FROM golang:1.26.5-alpine AS build

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG TARGETARCH=amd64
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/Gabriel0110/changegate/internal/buildinfo.Version=${VERSION} -X github.com/Gabriel0110/changegate/internal/buildinfo.Commit=${COMMIT} -X github.com/Gabriel0110/changegate/internal/buildinfo.Date=${DATE}" \
    -o /out/changegate \
    ./cmd/changegate

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/changegate /changegate
USER 65532:65532
ENTRYPOINT ["/changegate"]
