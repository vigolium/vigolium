#!/bin/bash
set -e

USERNAME="${SSH_USER:-deploy}"
PASSWORD="${SSH_PASSWORD:-deploy123}"

# Create user if it doesn't exist
if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
    usermod -aG sudo "$USERNAME"
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME
fi

# Setup SSH key auth if a public key is mounted
if [ -f /tmp/ssh-pubkey/authorized_keys ]; then
    mkdir -p /home/$USERNAME/.ssh
    cp /tmp/ssh-pubkey/authorized_keys /home/$USERNAME/.ssh/authorized_keys
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
    chmod 700 /home/$USERNAME/.ssh
    chmod 600 /home/$USERNAME/.ssh/authorized_keys
fi

# Enable password auth
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
