FROM docker.io/library/python:3.14-slim AS BUILD

ARG BRANCH main

RUN set -eux; \

apt-get update; \
apt-get install -y --no-install-recommends git build-essential; \

python3 -m venv /opt/cvproxy; \
/opt/cvproxy/bin/python3 -m pip install --upgrade git+https://github.com/cmason3/cvproxy.git@${BRANCH}; \
/opt/cvproxy/bin/python3 -m pip uninstall -y pip


FROM docker.io/library/python:3.14-slim

COPY --from=BUILD /opt/cvproxy /opt/cvproxy

ENV VIRTUAL_ENV /opt/cvproxy
ENV PATH /opt/cvproxy/bin:${PATH}

ENTRYPOINT [ "python3", "-u", "-m", "cvproxy", "-s", "-l", "0.0.0.0", "-p", "8080" ]
