# Development-only Linux image. A public release still requires independent audit.
FROM golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY web/workbench ./web/workbench
RUN mkdir -p /out && \
    CGO_ENABLED=0 go build -trimpath -o /out/rootwelld ./cmd/rootwelld && \
    CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -o /out/rootwell.wasm ./cmd/rootwell-browser && \
    cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" /out/wasm_exec.js && \
    CGO_ENABLED=0 go test -c -o /out/volume-drill.test ./internal/instanceaccess && \
    CGO_ENABLED=0 go test -c -o /out/ca-trust-drill.test ./internal/acmestaging

FROM scratch AS volume-drill
COPY --from=build /out/volume-drill.test /volume-drill.test
COPY --from=build /src/web/workbench/rootwell-demo-certificate.pem /demo.pem
USER 65532:65532
ENTRYPOINT ["/volume-drill.test"]

# The HTTPS API needs normal public system roots, not staging issuance roots.
# Both the test and serving images inherit the exact same pinned-base bundle.
FROM scratch AS trust-base
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

FROM trust-base AS ca-trust-drill
COPY --from=build /out/ca-trust-drill.test /ca-trust-drill.test
USER 65532:65532
ENTRYPOINT ["/ca-trust-drill.test"]

FROM trust-base
COPY --from=build /out/rootwelld /rootwelld
COPY --from=build /src/web/workbench /assets
COPY --from=build /out/rootwell.wasm /assets/rootwell.wasm
COPY --from=build /out/wasm_exec.js /assets/wasm_exec.js
USER 65532:65532
ENTRYPOINT ["/rootwelld"]
CMD ["serve", "/data", "/assets"]
