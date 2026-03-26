FROM python:3.12-slim

# Pinned tool versions — update ARGs to bump
ARG CHISEL_VERSION=1.11.4
ARG LIGOLO_VERSION=0.8.2
ARG IMPACKET_VERSION=0.13.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools iproute2 iputils-ping dnsutils tcpdump gcc libc6-dev \
    libffi-dev libssl-dev git curl socat proxychains-ng openssh-client \
    ruby ruby-dev make \
    && rm -rf /var/lib/apt/lists/*

# Evil-WinRM — WinRM shell for Windows targets
RUN gem install evil-winrm --no-document

# Responder — LLMNR/NBT-NS/mDNS poisoner
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder

# Python pentest tools (impacket, mitm6, dpapick3)
RUN pip install --no-cache-dir impacket==${IMPACKET_VERSION} mitm6 aioquic dpapick3

# Chisel — TCP/UDP tunnel over HTTP (pivoting)
RUN curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" \
    | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel

# Ligolo-ng proxy — TUN-based pivot proxy (attacker side)
RUN mkdir /tmp/ligolo \
    && curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_amd64.tar.gz" \
        | tar xzf - -C /tmp/ligolo/ \
    && find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; \
    && chmod +x /usr/local/bin/ligolo-proxy \
    && rm -rf /tmp/ligolo

ENV PATH="/opt/Responder:${PATH}"
WORKDIR /opt/Responder
ENTRYPOINT ["/bin/bash"]
