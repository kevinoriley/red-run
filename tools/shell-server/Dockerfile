FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools iproute2 iputils-ping dnsutils tcpdump gcc libffi-dev \
    libssl-dev git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder
RUN pip install --no-cache-dir impacket mitm6

ENV PATH="/opt/Responder:${PATH}"
WORKDIR /work
ENTRYPOINT ["/bin/bash"]
