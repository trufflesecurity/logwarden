#TODO generate build/dockerfile config
FROM ubuntu:22.10
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends \
          language-pack-en \
          ca-certificates \
          lsb-release \
          git \
      && apt-get purge -y \
          krb5-locales \
      && apt-get clean -y \
      && apt-get autoremove -y \
      && rm -rf /tmp/* /var/tmp/* \
      && rm -rf /var/lib/apt/lists/* \
      && update-ca-certificates
ENTRYPOINT [ "" ]
