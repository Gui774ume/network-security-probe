FROM debian

RUN apt-get update && \
	apt-get install -y netcat-traditional curl httpie wget dnsutils

COPY bin/pong /usr/local/bin/pong
COPY cmd/pong/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
CMD ["pong"]
