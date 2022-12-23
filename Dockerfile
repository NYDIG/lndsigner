ARG gover=1.19.5

FROM golang:$gover

ARG goplatform=amd64
ARG cppplatform=x86_64
ARG lnd=v0.15.5-beta
ARG bitcoind=24.0.1
ARG vault=1.12.2

RUN apt update && apt-get install -y zip

RUN cd /root && \
    wget https://bitcoincore.org/bin/bitcoin-core-$bitcoind/bitcoin-${bitcoind}-${cppplatform}-linux-gnu.tar.gz && \
    tar xfz bitcoin-$bitcoind-$cppplatform-linux-gnu.tar.gz && \
    mv bitcoin-$bitcoind/bin/* /usr/local/bin/ && \
    wget https://github.com/lightningnetwork/lnd/releases/download/$lnd/lnd-linux-$goplatform-$lnd.tar.gz && \
    tar xfz lnd-linux-$goplatform-$lnd.tar.gz && \
    mv lnd-linux-$goplatform-$lnd/* /usr/local/bin/ && \
    wget https://releases.hashicorp.com/vault/$vault/vault_${vault}_linux_${goplatform}.zip && \
    unzip vault_${vault}_linux_${goplatform}.zip && \
    mv vault /usr/local/bin/ && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    git config --global --add safe.directory /app && \
    echo "export PATH='$PATH:/usr/local/go/bin:/root/go/bin'" >> .bashrc

VOLUME [ "/app" ]

WORKDIR /app
