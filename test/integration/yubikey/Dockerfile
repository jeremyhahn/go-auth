# Stage 1: Get Go 1.25
FROM golang:1.25-bookworm AS gobuilder

# Stage 2: Build YubiKey validation server with Ubuntu 18.04
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV KEYS_AMOUNT=10
ENV DB_PASSWORD=testpassword

# Copy Go from the builder stage
COPY --from=gobuilder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        debconf \
        apache2 \
        php \
        php-mysql \
        php-curl \
        mysql-server \
        wget \
        gnupg \
        rng-tools \
        make \
        libdbi-perl \
        libdbd-mysql-perl \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /root /var/lock/apache2 /var/run/apache2 /var/log/supervisor /usr/share/yubikey-ksm /usr/share/yubikey-val

# Download and install YubiKey KSM from source
RUN cd /tmp && \
    wget -q https://developers.yubico.com/yubikey-ksm/Releases/yubikey-ksm-1.15.tgz && \
    tar xzf yubikey-ksm-1.15.tgz && \
    cd yubikey-ksm-1.15 && \
    make install

# Download and install YubiKey VAL from source
RUN cd /tmp && \
    wget -q https://developers.yubico.com/yubikey-val/Releases/yubikey-val-2.41.tgz && \
    tar xzf yubikey-val-2.41.tgz && \
    cd yubikey-val-2.41 && \
    make install

# Configure MySQL to start without systemd
RUN mkdir -p /var/run/mysqld && \
    chown -R mysql:mysql /var/run/mysqld

# Start MySQL, configure databases, and initialize schemas in one step
RUN service mysql start && \
    sleep 5 && \
    mysql -e "CREATE DATABASE IF NOT EXISTS ykval;" && \
    mysql -e "CREATE DATABASE IF NOT EXISTS ykksm;" && \
    mysql -e "CREATE USER IF NOT EXISTS 'ykval_verifier'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';" && \
    mysql -e "CREATE USER IF NOT EXISTS 'ykksm_verifier'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';" && \
    mysql -e "GRANT ALL ON ykval.* TO 'ykval_verifier'@'localhost';" && \
    mysql -e "GRANT ALL ON ykksm.* TO 'ykksm_verifier'@'localhost';" && \
    mysql -e "FLUSH PRIVILEGES;" && \
    mysql ykval < /usr/share/doc/yubikey-val/ykval-db.sql && \
    mysql ykksm < /usr/share/doc/yubikey-ksm/ykksm-db.sql && \
    service mysql stop

# Configure YubiKey VAL
RUN echo "<?php\n\
\$baseParams = array();\n\
\$baseParams['__YKVAL_DB_DSN__'] = 'mysql:dbname=ykval;host=localhost';\n\
\$baseParams['__YKVAL_DB_USER__'] = 'ykval_verifier';\n\
\$baseParams['__YKVAL_DB_PW__'] = '${DB_PASSWORD}';\n\
\$baseParams['__YKVAL_SYNC_POOL__'] = array();\n\
\$baseParams['__YKKSM_URL__'] = 'http://localhost/wsapi/decrypt?otp=';\n\
?>" > /etc/yubico/val/ykval-config.php

# Configure YubiKey KSM
RUN echo "<?php\n\
\$baseParams = array();\n\
\$baseParams['__YKKSM_DB_DSN__'] = 'mysql:dbname=ykksm;host=localhost';\n\
\$baseParams['__YKKSM_DB_USER__'] = 'ykksm_verifier';\n\
\$baseParams['__YKKSM_DB_PW__'] = '${DB_PASSWORD}';\n\
?>" > /etc/yubico/ksm/ykksm-config.php

# Generate GPG key for encrypting YubiKey secrets
RUN rngd -r /dev/urandom && \
    echo "Key-Type: RSA\nKey-Length: 2048\nName-Real: YubiKey Test\nName-Email: test@example.com\nExpire-Date: 0\n%no-protection\n%commit" > /root/gpg.conf && \
    gpg --batch --gen-key /root/gpg.conf

# Generate test YubiKey credentials and create/export client credentials
RUN service mysql start && \
    sleep 5 && \
    ykksm-gen-keys --urandom 1 ${KEYS_AMOUNT} > /root/keys.txt && \
    gpg --trust-model always -a -s --encrypt -r "YubiKey Test" < /root/keys.txt > /root/encrypted_keys.txt && \
    ykksm-import < /root/encrypted_keys.txt && \
    ykval-gen-clients --urandom --email "test@example.com" 1 > /root/client.txt && \
    cat /root/client.txt && \
    service mysql stop

# Configure Apache
RUN a2enmod rewrite && \
    a2enmod php7.2 || true

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start MySQL\n\
service mysql start\n\
\n\
# Wait for MySQL\n\
until mysql -e "SELECT 1" >/dev/null 2>&1; do\n\
    sleep 1\n\
done\n\
\n\
# Start Apache\n\
service apache2 start\n\
\n\
echo "========================================"\n\
echo "YubiKey Validation Server Ready"\n\
echo "========================================"\n\
if [ -f /root/client.txt ]; then\n\
    CLIENT_ID=$(cut -d"," -f1 /root/client.txt)\n\
    CLIENT_KEY=$(cut -d"," -f2 /root/client.txt)\n\
    echo "Client ID: ${CLIENT_ID}"\n\
    echo "Client Key: ${CLIENT_KEY}"\n\
fi\n\
echo "========================================"\n\
\n\
if [ -f /root/keys.txt ]; then\n\
    FIRST_KEY=$(grep -v "^#" /root/keys.txt | head -n 1)\n\
    if [ -n "$FIRST_KEY" ]; then\n\
        echo "Test Key:"\n\
        echo "  Public ID: $(echo $FIRST_KEY | cut -d"," -f2)"\n\
        echo "  Private ID: $(echo $FIRST_KEY | cut -d"," -f3)"\n\
        echo "  Secret: $(echo $FIRST_KEY | cut -d"," -f4)"\n\
    fi\n\
fi\n\
echo "========================================"\n\
\n\
cp -r /workspace-src /workspace\n\
cd /workspace\n\
\n\
export TEST_CLIENT_ID=$(cut -d"," -f1 /root/client.txt 2>/dev/null || echo "1")\n\
export TEST_CLIENT_KEY=$(cut -d"," -f2 /root/client.txt 2>/dev/null || echo "dGVzdGtleQ==")\n\
\n\
echo "Running integration tests..."\n\
CGO_ENABLED=0 go test -v -tags integration ./test/integration/yubikey/...\n\
' > /start.sh && chmod +x /start.sh

# Copy Go workspace
WORKDIR /workspace-src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

EXPOSE 80

CMD ["/start.sh"]
