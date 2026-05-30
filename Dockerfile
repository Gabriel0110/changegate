FROM golang:1.26.3-alpine AS build

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG TARGETARCH=amd64
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/Gabriel0110/changegate/internal/buildinfo.Version=${VERSION} -X github.com/Gabriel0110/changegate/internal/buildinfo.Commit=${COMMIT} -X github.com/Gabriel0110/changegate/internal/buildinfo.Date=${DATE}" \
    -o /out/changegate \
    ./cmd/changegate

FROM scratch
COPY --from=build /out/changegate /changegate
ENTRYPOINT ["/changegate"]
