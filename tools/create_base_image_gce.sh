#!/bin/bash

# Copyright 2018 Google Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -x
set -o errexit
shopt -s extglob

# If "true" install host orchestration capabilities.
host_orchestration_flag="false"

while getopts ":o" flag; do
    case "${flag}" in
        o) host_orchestration_flag="true";;
    esac
done

sudo apt-get update

sudo apt install -y debconf-utils

# Avoids blocking "Default mirror not found" popup prompt when pbuilder is installed.
echo "pbuilder        pbuilder/mirrorsite     string  https://deb.debian.org/debian" | sudo debconf-set-selections

# Stuff we need to get build support
sudo apt install -y debhelper ubuntu-dev-tools equivs "${extra_packages[@]}"

function install_bazel() {
  # From https://bazel.build/install/ubuntu
  echo "Installing bazel"
  sudo apt install apt-transport-https curl gnupg -y
  curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
  sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
  # bazel needs the zip command to gather test outputs but doesn't depend on it
  sudo apt-get update && sudo apt-get install -y bazel zip unzip
}

install_bazel

# Resize
sudo apt install -y cloud-utils
sudo apt install -y cloud-guest-utils
sudo apt install -y fdisk
sudo growpart /dev/sdb 1 || /bin/true
sudo e2fsck -f -y /dev/sdb1 || /bin/true
sudo resize2fs /dev/sdb1

# Install the cuttlefish build deps

for dsc in *.dsc; do
  yes | sudo mk-build-deps -i "${dsc}" -t apt-get
done

# Installing the build dependencies left some .deb files around. Remove them
# to keep them from landing on the image.
yes | rm -f *.deb

for dsc in *.dsc; do
  # Unpack the source and build it

  dpkg-source -x "${dsc}"
  dir="$(basename "${dsc}" .dsc)"
  dir="${dir/_/-}"
  pushd "${dir}/"
  debuild -uc -us
  popd
done

# Now gather all of the relevant .deb files to copy them into the image
debs=(!(cuttlefish-orchestration*).deb)
if [[ "${host_orchestration_flag}" == "true" ]]; then
  debs+=( cuttlefish-orchestration*.deb )
fi

tmp_debs=()
for i in "${debs[@]}"; do
  tmp_debs+=(/tmp/"$(basename "$i")")
done

# Now install the packages on the disk
sudo mkdir -p /mnt/image
sudo mount /dev/sdb1 /mnt/image
cp "${debs[@]}" /mnt/image/tmp
sudo mount -t sysfs none /mnt/image/sys
sudo mount -t proc none /mnt/image/proc
sudo mount --bind /boot/efi /mnt/image/boot/efi
sudo mount --bind /dev/ /mnt/image/dev
sudo mount --bind /dev/pts /mnt/image/dev/pts
sudo mount --bind /run /mnt/image/run
# resolv.conf is needed on Debian but not Ubuntu
if [ ! -f /mnt/image/etc/resolv.conf ]; then
  sudo cp /etc/resolv.conf /mnt/image/etc/
fi
sudo chroot /mnt/image /usr/bin/apt update
sudo chroot /mnt/image /usr/bin/apt install -y "${tmp_debs[@]}"

# Install JDK.
#
# JDK it's not required to launch a CF device. It's required to run
# some of Tradefed tests that are run from the CF host side like
# some CF gfx tests, adb tests, etc.
sudo chroot /mnt/image /usr/bin/wget -P /usr/java https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz
# https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz.sha256
export JDK21_SHA256SUM=a2def047a73941e01a73739f92755f86b895811afb1f91243db214cff5bdac3f
if ! echo "$JDK21_SHA256SUM /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz" | sudo chroot /mnt/image /usr/bin/sha256sum -c ; then
  echo "** ERROR: KEY MISMATCH **"; popd >/dev/null; exit 1;
fi
sudo chroot /mnt/image /usr/bin/tar xvzf /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz -C /usr/java
sudo chroot /mnt/image /usr/bin/rm /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz
echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/environment >/dev/null
echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
echo 'PATH=$JAVA_HOME/bin:$PATH' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null

# install tools dependencies
sudo chroot /mnt/image /usr/bin/apt install -y unzip bzip2 lzop
sudo chroot /mnt/image /usr/bin/apt install -y aapt
sudo chroot /mnt/image /usr/bin/apt install -y screen # needed by tradefed

sudo chroot /mnt/image /usr/bin/find /home -ls
sudo chroot /mnt/image /usr/bin/apt install -t bookworm -y linux-image-cloud-amd64

# update QEMU version to most recent backport
sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-x86 -t bookworm
sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-arm -t bookworm
sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-misc -t bookworm

# Install GPU driver dependencies
sudo cp install_nvidia.sh /mnt/image/
sudo chroot /mnt/image /usr/bin/bash install_nvidia.sh
sudo rm /mnt/image/install_nvidia.sh

# Vulkan loader
sudo chroot /mnt/image /usr/bin/apt install -y libvulkan1 -t bookworm

# Wayland-server needed to have Nvidia driver fail gracefully when attempting to
# use the EGL API on GCE instances without a GPU.
sudo chroot /mnt/image /usr/bin/apt install -y libwayland-server0 -t bookworm

# Clean up the builder's version of resolv.conf
sudo rm /mnt/image/etc/resolv.conf

# Make sure the image has /var/empty, and allow unprivileged_userns_clone for
# minijail process sandboxing
sudo chroot /mnt/image /usr/bin/mkdir -p /var/empty
sudo tee /mnt/image/etc/sysctl.d/80-nsjail.conf >/dev/null <<EOF
kernel.unprivileged_userns_clone=1
EOF

# Skip unmounting:
#  Sometimes systemd starts, making it hard to unmount
#  In any case we'll unmount cleanly when the instance shuts down

echo IMAGE_WAS_CREATED
