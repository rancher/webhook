# Copyright (C) 2022, Oracle and/or its affiliates.

FROM ghcr.io/oracle/oraclelinux:7-slim

ARG user=webhook

RUN echo "$user:x:1000:1000::/home/$user:/bin/bash" >> /etc/passwd && \
    echo "$user:x:1000:" >> /etc/group && \
    mkdir /home/$user && \
    chown -R $user:$user /home/$user

COPY bin/webhook /usr/bin/
COPY LICENSE README.md THIRD_PARTY_LICENSES.txt SECURITY.md /licenses/

USER $user

CMD ["webhook"]
