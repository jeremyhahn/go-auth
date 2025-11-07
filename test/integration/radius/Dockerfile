FROM golang:1.25-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        freeradius \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY pkg/radius/testdata/certs/ /etc/freeradius/3.0/certs/
COPY pkg/radius/testdata/server/radsec.conf /etc/freeradius/3.0/sites-enabled/radsec
COPY pkg/radius/testdata/server/mods-available/eap /etc/freeradius/3.0/mods-available/eap
COPY pkg/radius/testdata/server/mods-available/eap /etc/freeradius/3.0/mods-enabled/eap
RUN chown -R freerad:freerad /etc/freeradius/3.0/certs \
    && mkdir -p /etc/freeradius/3.0/tmp \
    && chown freerad:freerad /etc/freeradius/3.0/tmp
RUN printf 'radiususer Cleartext-Password := "radiuspass"\n' > /etc/freeradius/3.0/users \
    && printf '"radius-client" Auth-Type := EAP\n' >> /etc/freeradius/3.0/users

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0
CMD ["bash", "-lc", "freeradius -f -l stdout -x & PID=$!; sleep 5; /usr/local/go/bin/go test -v -tags integration ./test/integration/radius; STATUS=$?; kill $PID; exit $STATUS"]
