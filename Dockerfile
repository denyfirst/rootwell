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
    CGO_ENABLED=0 go test -c -o /out/volume-drill.test ./internal/instanceaccess

FROM scratch AS volume-drill
COPY --from=build /out/volume-drill.test /volume-drill.test
COPY --from=build /src/web/workbench/rootwell-demo-certificate.pem /demo.pem
USER 65532:65532
ENTRYPOINT ["/volume-drill.test"]

FROM scratch
COPY --from=build /out/rootwelld /rootwelld
COPY --from=build /src/web/workbench /assets
COPY --from=build /out/rootwell.wasm /assets/rootwell.wasm
COPY --from=build /out/wasm_exec.js /assets/wasm_exec.js
USER 65532:65532
ENTRYPOINT ["/rootwelld"]
CMD ["serve", "/data", "/assets"]
