FROM registry.suse.com/bci/bci-micro:15.5

ARG user=webhook

RUN echo "$user:x:1000:1000::/home/$user:/bin/bash" >> /etc/passwd && \
    echo "$user:x:1000:" >> /etc/group && \
    mkdir /home/$user && \
    chown -R $user:$user /home/$user

COPY bin/webhook /usr/bin/

USER $user

CMD ["webhook"]

# These labels are here for backward compatibility after having moved from
# drone to GHA
ARG LABEL_CREATED=1970-01-01T00:00:00Z
ARG LABEL_REVISION=dev
ARG LABEL_SOURCE=https://github.com/rancher/webhook.git
ARG LABEL_URL=https://github.com/rancher/webhook

LABEL org.opencontainers.image.created=$LABEL_CREATED
LABEL org.opencontainers.image.revision=$LABEL_REVISION
LABEL org.opencontainers.image.source=$LABEL_SOURCE
LABEL org.opencontainers.image.url=$LABEL_URL
