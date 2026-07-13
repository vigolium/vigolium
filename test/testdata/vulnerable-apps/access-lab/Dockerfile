# Deliberately vulnerable app — do not deploy. Stdlib-only, so the build is tiny
# and offline.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /access-lab .

FROM gcr.io/distroless/static-debian12
COPY --from=build /access-lab /access-lab
ENV ACCESS_LAB_ADDR=":9899"
EXPOSE 9899
ENTRYPOINT ["/access-lab"]
