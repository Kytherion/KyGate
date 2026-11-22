# KyGate single binary. The console is embedded; no Node or Python is needed.
# The Community edition by default. With the Enterprise sources present:
#   docker build --build-arg TAGS=enterprise -t kygate-ee:0.1.2 .
FROM golang:1.26-alpine AS build
ARG TAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags "${TAGS}" -trimpath -ldflags="-s -w" -o /out/kygate ./cmd/kygate

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 kygate \
 && mkdir /data && chown kygate:kygate /data
# /data must exist and belong to kygate before VOLUME: a new named volume takes
# its owner from the image, and KyGate runs as kygate, not root.
USER kygate
ENV KYGATE_DATA_DIR=/data \
    KYGATE_LISTEN=0.0.0.0:4000 \
    KYGATE_CONSOLE_LISTEN=0.0.0.0:4001
VOLUME /data
EXPOSE 4000 4001
COPY --from=build /out/kygate /usr/local/bin/kygate
ENTRYPOINT ["kygate"]
CMD ["serve"]
