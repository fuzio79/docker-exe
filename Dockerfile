FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# GID 984 is the host group that owns /var/run/docker.sock. The service runs as
# a non-root user that must be a member of *that* group to open the socket, so
# the build creates it with the host's numeric GID. The number is host-specific
# -- find yours with:
#
#     getent group docker        # or: stat -c '%g' /var/run/docker.sock
#
# and change 984 below if it differs. (It is not a secret and not a hardcoded
# permission grant: it is only the numeric identity of the docker group.)
#
# Note that membership of this group IS effectively root on the host. That is
# inherent to mounting the docker socket and is not something this image can
# avoid; see SECURITY.md.
RUN groupadd -g 984 docker \
  && useradd -r -u 1000 -g docker docker-exec

USER docker-exec

EXPOSE 8091

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8091"]
