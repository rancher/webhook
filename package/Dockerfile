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
LABEL org.opencontainers.image.created=$LABEL_CREATED

ARG LABEL_REVISION=dev
LABEL org.opencontainers.image.revision=$LABEL_REVISION

ARG LABEL_SOURCE=https://github.com/rancher/webhook.git
LABEL org.opencontainers.image.source=$LABEL_SOURCE

ARG LABEL_URL=https://github.com/rancher/webhook
LABEL LABEL org.opencontainers.image.url=$LABEL_URL
