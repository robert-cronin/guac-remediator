# Dockerfile
# multi-stage build

# stage 1: build
FROM golang:1.23-alpine AS build
WORKDIR /app

# copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# copy entire project
COPY . .

# build static binary
RUN CGO_ENABLED=0 go build -o guac-remediator ./cmd/guac-remediator

# stage 2: final minimal image
FROM gcr.io/distroless/static:nonroot
COPY --from=build /app/guac-remediator /bin/guac-remediator
ENTRYPOINT ["/bin/guac-remediator"]
