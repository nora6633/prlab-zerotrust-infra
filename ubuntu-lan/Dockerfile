FROM ubuntu:24.04

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
      systemd systemd-sysv \
      openssh-server sudo \
      python3 python3-pip \
      curl ca-certificates gnupg git \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && rm -f /lib/systemd/system/multi-user.target.wants/* \
             /etc/systemd/system/*.wants/* \
             /lib/systemd/system/local-fs.target.wants/* \
             /lib/systemd/system/sockets.target.wants/*udev* \
             /lib/systemd/system/sockets.target.wants/*initctl* \
             /lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup* \
             /lib/systemd/system/systemd-update-utmp*

RUN useradd -m -s /bin/bash dev && \
    echo 'dev:devpass' | chpasswd && \
    usermod -aG sudo dev && \
    echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev && \
    mkdir -p /home/dev/.ssh && chmod 700 /home/dev/.ssh

COPY authorized_keys /home/dev/.ssh/authorized_keys
RUN chown -R dev:dev /home/dev/.ssh && chmod 600 /home/dev/.ssh/authorized_keys

RUN systemctl enable ssh

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
