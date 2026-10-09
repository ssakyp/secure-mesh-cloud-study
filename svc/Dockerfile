FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/svc .

FROM alpine:3.23
# curl is used by scripts/attack_matrix.py via `kubectl exec`; the service itself needs nothing
RUN apk add --no-cache curl ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/svc /usr/local/bin/svc
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/svc"]
