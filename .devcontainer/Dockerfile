FROM --platform=${TARGETPLATFORM} golang:1.20.5-alpine
ARG TARGETPLATFORM

ARG USERNAME=vhnvn
ARG USER_UID=1000
ARG USER_GID=$USER_UID


# dev base
RUN apk add curl ca-certificates gnupg lldb python3 gcc libc-dev bash iptables bind-tools socat git tzdata openssl perf lld

RUN addgroup --gid $USER_GID $USERNAME \
    && adduser --disabled-password --uid $USER_UID --ingroup $USERNAME $USERNAME \
    && apk add sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

ENV GOPATH=/home/$USERNAME/go
ENV PATH=$PATH:$GOPATH/bin
USER $USERNAME


RUN mkdir -p $GOPATH && \
    go install -v golang.org/x/tools/gopls@latest && \
    go install -v github.com/ramya-rao-a/go-outline@v0.0.0-20210608161538-9736a4bde949 && \
    go install -v golang.org/x/tools/cmd/goimports@latest

ENTRYPOINT [ "/bin/bash" ]

