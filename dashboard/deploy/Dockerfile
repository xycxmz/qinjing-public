# Multi-stage build for the qinjing dashboard (pure stdlib, CGO off).
# Build context = the dashboard/ directory:
#   docker build -f deploy/Dockerfile -t qinjing-dashboard .
# Data is baked at build time; to refresh without rebuild, mount a volume over
# /dashboard_data.json and send SIGHUP (docker kill -s HUP <ctr>).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates ./templates
COPY static ./static
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/dashboard .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/dashboard /dashboard
COPY dashboard_data.json /dashboard_data.json
EXPOSE 8090
# Bind all interfaces inside the container; put a TLS reverse proxy in front.
ENTRYPOINT ["/dashboard", "--addr", "0.0.0.0:8090", "--data", "/dashboard_data.json"]