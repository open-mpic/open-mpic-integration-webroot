FROM ubuntu:latest

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update packages and install Unbound with required dependencies
RUN apt-get update && \
    apt-get install -y \
    openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Dist/package upgrade
RUN apt-get update && apt-get dist-upgrade -y

WORKDIR /server

COPY tls-alpn-server.sh /server/tls-alpn-server.sh

EXPOSE 443

CMD ["./tls-alpn-server.sh"]
