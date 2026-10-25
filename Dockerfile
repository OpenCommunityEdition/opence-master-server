# The master as a static binary on a distroless image, run as a non-root
# user. The database, the master key and the updates it installs (bin/)
# live in /data (a volume).
# (the build runs on the builder's platform and cross-compiles: a
# multi-arch image builds without emulating each target)
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS=linux TARGETARCH=amd64 TARGETVARIANT=
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X github.com/OpenCommunityEdition/opence-master-server/internal/core.Version=${VERSION}" \
	-o /out/opence-master ./cmd/opence-master \
	&& mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opence-master /usr/local/bin/opence-master
COPY --from=build --chown=65532:65532 /out/data /data
ENV MASTER_DB=/data/master.db \
	MASTER_KEY=/data/master.key \
	MASTER_LISTEN=0.0.0.0:8090
VOLUME /data
EXPOSE 8090
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/opence-master", "health"]
ENTRYPOINT ["/usr/local/bin/opence-master"]
CMD ["serve"]
