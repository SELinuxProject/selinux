#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -ev

TEST_RUNNER="scripts/ci/fedora-test-runner.sh"

#
# Variables for controlling the Fedora Image version and download URLs.
#
MAJOR_VERSION="32"
MINOR_VERSION="1.6"

BASE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases"
IMAGE_BASE_NAME="Fedora-Cloud-Base-$MAJOR_VERSION-$MINOR_VERSION.x86_64"
IMAGE_URL="$BASE_URL/$MAJOR_VERSION/Cloud/x86_64/images/$IMAGE_BASE_NAME.raw.xz"
CHECK_URL="$BASE_URL/$MAJOR_VERSION/Cloud/x86_64/images/Fedora-Cloud-$MAJOR_VERSION-$MINOR_VERSION-x86_64-CHECKSUM"
GPG_URL="https://getfedora.org/static/fedora.gpg"

#
# Travis gives us 7.5GB of RAM and two cores:
# https://docs.travis-ci.com/user/reference/overview/
#
MEMORY=4096
VCPUS="$(nproc)"

# Install these here so other builds don't have to wait on these deps to download and install
sudo apt-get install qemu-kvm libvirt-bin virtinst bridge-utils cpu-checker libguestfs-tools

sudo usermod -a -G kvm,libvirt,libvirt-qemu "$USER"

# Verify that KVM is working, useful if Travis ever changes anything.
kvm-ok

sudo systemctl enable libvirtd
sudo systemctl start libvirtd

# Set up a key so we can ssh into the VM
ssh-keygen -N "" -f "$HOME/.ssh/id_rsa"

#
# Get the Fedora Cloud Image, It is a base image that small and ready to go, extract it and modify it with virt-sysprep
#  - https://alt.fedoraproject.org/en/verify.html
cd "$HOME"
wget "$IMAGE_URL"

# Verify the image
curl "$GPG_URL" | gpg --import
wget "$CHECK_URL"
gpg --verify-files ./*-CHECKSUM
sha256sum --ignore-missing -c ./*-CHECKSUM

# Extract the image
unxz -T0 "$IMAGE_BASE_NAME.raw.xz"

# Search is needed for $HOME so virt service can access the image file.
chmod a+x "$HOME"

#
# Modify the virtual image to:
#   - Enable a login, we just use root
#   - Enable passwordless login
#     - Force a relabel to fix labels on ssh keys
#
sudo virt-sysprep -a "$IMAGE_BASE_NAME.raw" \
  --root-password password:123456 \
  --hostname fedoravm \
  --append-line '/etc/ssh/sshd_config:PermitRootLogin yes' \
  --append-line '/etc/ssh/sshd_config:PubkeyAuthentication yes' \
  --mkdir /root/.ssh \
  --upload "$HOME/.ssh/id_rsa.pub:/root/.ssh/authorized_keys" \
  --chmod '0600:/root/.ssh/authorized_keys' \
  --run-command 'chown root:root /root/.ssh/authorized_keys' \
  --copy-in "$TRAVIS_BUILD_DIR:/root" \
  --network \
  --selinux-relabel

#
# Now we create a domain by using virt-install. This not only creates the domain, but runs the VM as well
# It should be ready to go for ssh, once ssh starts.
#
sudo virt-install \
  --name fedoravm \
  --memory $MEMORY \
  --vcpus $VCPUS \
  --disk "$IMAGE_BASE_NAME.raw" \
  --import --noautoconsole

#
# Here comes the tricky part, we have to figure out when the VM comes up AND we need the ip address for ssh. So we
# can check the net-dhcp leases, for our host. We have to poll, and we will poll for up to 3 minutes in 6 second
# intervals, so 30 poll attempts (0-29 inclusive).
#
# We have a full reboot + relabel, so first sleep gets us close
#
sleep 30
for i in $(seq 0 29); do
    echo "loop $i"
    sleep 6s
    # Get the leases, but tee it so it's easier to debug
    sudo virsh net-dhcp-leases default | tee dhcp-leases.txt

    # get our ipaddress
    ipaddy="$(grep fedoravm dhcp-leases.txt | awk '{print $5}' | cut -d'/' -f 1-1)"
    if [ -n "$ipaddy" ]; then
        # found it, we're done looking, print it for debug logs
        echo "ipaddy: $ipaddy"
        break
    fi
    # it's empty/not found, loop back and try again.
done

# Did we find it? If not die.
if [ -z "$ipaddy" ]; then
    echo "ipaddy zero length, exiting with error 1"
    exit 1
fi

#
# Great we have a host running, ssh into it. We specify -o so
# we don't get blocked on asking to add the servers key to
# our known_hosts. Also, we need to forward the project directory
# so forks know where to go.
#
project_dir="$(basename "$TRAVIS_BUILD_DIR")"
ssh -tt -o StrictHostKeyChecking=no -o LogLevel=QUIET "root@$ipaddy" "SELINUX_DIR=/root/$project_dir /root/$project_dir/$TEST_RUNNER"

exit 0
