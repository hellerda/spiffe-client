FROM alpine:latest

RUN apk --no-cache add bash curl git jq openssl

# For spiffe-client to be able to attach to the shared UNIX socket of a SPIRE Agent...
RUN mkdir -p /tmp/spire-agent/public/

WORKDIR /

COPY bin/* /bin/

RUN \
echo -e > /.profile \
"set -o vi\n"\
"alias ll='ls -l'\n"\
"alias lh='ls -lh'\n"\
"alias la='ls -la'\n"\
"alias psgrep='ps -ef | grep -v grep | grep'\n"\
"#PS1='[\u@\h \W]\\$ '\n"\
"#PS1='[\u@spiffe-client \W]\\$ '\n"\
"PS1='[pod@spiffe-client \w]\\$ '"

CMD ["/bin/spiffe-client", "--help"]
