FROM debian

RUN apt-get update && \
	apt-get install -y netcat-traditional curl httpie wget dnsutils

COPY bin/ping /usr/local/bin/go-ping
COPY bin/nspbench /usr/local/bin/nspbench
COPY cmd/ping/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
CMD ["go-ping"]
