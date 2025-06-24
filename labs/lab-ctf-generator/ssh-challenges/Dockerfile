
FROM ubuntu:20.04

# Install SSH and tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    vim \
    gcc \
    python3 \
    && mkdir /var/run/sshd

# Create CTF user
RUN useradd -m -s /bin/bash ctfuser && \
    echo 'ctfuser:challenge123' | chpasswd

# Setup SUID binary for privilege escalation
COPY custom_binary /usr/bin/custom_binary
RUN chmod 4755 /usr/bin/custom_binary

# SSH configuration
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
