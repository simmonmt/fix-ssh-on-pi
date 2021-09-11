#!/bin/bash
# MIT License
# Copyright (c) 2017 Ken Fallon http://kenfallon.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# v1.1 - changes to reflect that the sha_sum is now SHA-256
# v1.2 - Changes to split settings to different file, and use losetup
# v1.3 - Removed requirement to use xmllint (Thanks MachineSaver)
#        Added support for wifi mac naming (Thanks danielo515)
#        Moved ethernet naming to firstboot.sh

# Credits to:
# - http://hackerpublicradio.org/correspondents.php?hostid=225
# - https://gpiozero.readthedocs.io/en/stable/pi_zero_otg.html#legacy-method-sd-card-required
# - https://github.com/nmcclain/raspberian-firstboot

# You should not need to change anything beyond here.

set -e

PROGNAME=$(basename "$0")

function die () {
    echo "${PROGNAME}: $@" 2>&1
    exit 1
}

function usage () {
    echo "Usage: ${PROGNAME} ini_file" >&2
    exit 2
}

function crypt_password () {
    python3 -c "import crypt; print(crypt.crypt('${1}', crypt.mksalt(crypt.METHOD_SHA512)))"
}

[[ $# -ne 1 ]] && usage

settings_file="$1"
source "${settings_file}" || die "failed to read settings file ${settings_file}"

if [[ -n "${root_password_clear}" ]] ; then
    echo "Encrypting cleartext root password"
    root_password="$(crypt_password "${root_password_clear}")"
fi
if [[ -n "${pi_password_clear}" ]] ; then
    echo "Encrypting cleartext pi password"
    pi_password="$(crypt_password "${pi_password_clear}")"
fi

required_variables=(
  root_password
  pi_password
  public_key_file
  work_dir
)

for variable in "${required_variables[@]}" ; do
    if [[ -z ${!variable+x} ]]; then   # indirect expansion here
        die "\"${variable}\" missing from \""${settings_file}"\""
    fi
done

required_commands=(
    7z
    python3
    sha256sum
    wget
)

for command in "${required_commands[@]}" ; do
    which ${command} >/dev/null 2>&1 || die "command ${command} is required"
done

[[ $(id -u) -eq 0 ]] || die "must be run as root"

if [ ! -e "${public_key_file}" ]; then
    echo "Can't find the public key file \"${public_key_file}\""
    echo "You can create one using:"
    echo "   ssh-keygen -t ed25519 -f ./${public_key_file} -C \"Raspberry Pi keys\""
    die "invalid public key file"
fi

image_to_download="https://downloads.raspberrypi.org/raspios_full_armhf_latest"
url_base="https://downloads.raspberrypi.org/raspios_full_armhf/images/"
version="$( wget -q ${url_base} -O - | awk -F '"' '/raspios_full_armhf-/ {print $8}' - | sort -nr | head -1 )"
sha_file=$( wget -q ${url_base}/${version} -O - | awk -F '"' '/armhf-full.zip.sha256/ {print $8}' - )
sha_sum=$( wget -q "${url_base}/${version}/${sha_file}" -O - | awk '{print $1}' )
sdcard_mount="${work_dir}/mnt"

echo Found RaspiOS version ${version}

function umount_sdcard () {
    if findmnt "${sdcard_mount}" >/dev/null ; then
        umount "${sdcard_mount}" || die "failed to unmount \"${sdcard_mount}\""

        echo "Sucessfully unmounted \"${sdcard_mount}\""
        sync
    fi
}

function cleanup () {
    umount_sdcard
    [[ -n "${loop_base}" ]] && losetup --detach "${loop_base}"
}

trap cleanup EXIT

echo Cleaning work dir ${work_dir}
rm -fr "${work_dir}"/*

downloaded_zip="${work_dir}/raspbian_image.zip"

echo "Downloading image"
wget --quiet --continue "${image_to_download}" -O "${downloaded_zip}"

echo "Verifying SHA-1 of the downloaded image"

sha256sum "${downloaded_zip}" | grep -q ${sha_sum} || die "SHA sum didn't match"
echo "SHA sum matched"

img_dir="${work_dir}/img"

for dir in "${sdcard_mount}" ; do
    [[ -d "${dir}" ]] || mkdir ${dir}
done

image_name=$( 7z l "${downloaded_zip}" | awk '/-raspios-/ {print $NF}' )
[[ -z "${image_name}" ]] && die "failed to find name of image"

echo Extracting "${image_name}"
7z x "-o${work_dir}" -y "${downloaded_zip}" "${image_name}" >/dev/null

extracted_image="${work_dir}/${image_name}"

umount_sdcard
echo "Mounting the sdcard boot disk"

loop_base=$( losetup --partscan --find --show "${extracted_image}" )

echo "mounting ${loop_base}p1 on ${sdcard_mount}"
mount ${loop_base}p1 "${sdcard_mount}"
[[ -f "${sdcard_mount}/kernel.img" ]] || die "no kernel.img on boot disk"

[[ -n "${wifi_file}" ]] && cp "${wifi_file}" "${sdcard_mount}/wpa_supplicant.conf"
touch "${sdcard_mount}/ssh"

[[ -n "${first_boot}" ]] && cp "${first_boot}" "${sdcard_mount}/firstboot.sh"

umount_sdcard

echo "Mounting the sdcard root disk"
echo "mounting ${loop_base}p2 on ${sdcard_mount}"
mount ${loop_base}p2 "${sdcard_mount}"

[[ -f "${sdcard_mount}/etc/shadow" ]] || die "no /etc/shadow on root disk"

echo "Change the passwords and sshd_config file"

sed -e "s#^root:[^:]\+:#root:${root_password}:#" \
    -e  "s#^pi:[^:]\+:#pi:${pi_password}:#" \
    -i "${sdcard_mount}/etc/shadow"

sed -e 's;^#PasswordAuthentication.*$;PasswordAuthentication no;g' \
    -e 's;^PermitRootLogin .*$;PermitRootLogin no;g' \
    -i "${sdcard_mount}/etc/ssh/sshd_config"

mkdir "${sdcard_mount}/home/pi/.ssh"
chmod 0700 "${sdcard_mount}/home/pi/.ssh"
chown 1000:1000 "${sdcard_mount}/home/pi/.ssh"
cat ${public_key_file} >> "${sdcard_mount}/home/pi/.ssh/authorized_keys"
chown 1000:1000 "${sdcard_mount}/home/pi/.ssh/authorized_keys"
chmod 0600 "${sdcard_mount}/home/pi/.ssh/authorized_keys"

if [[ -n "${first_boot}" ]] ; then
    cat <<-EOF
	echo "[Unit]
	Description=FirstBoot
	After=network.target
	Before=rc-local.service
	ConditionFileNotEmpty=/boot/firstboot.sh

	[Service]
	ExecStart=/boot/firstboot.sh
	ExecStartPost=/bin/mv /boot/firstboot.sh /boot/firstboot.sh.done
	Type=oneshot
	RemainAfterExit=no

	[Install]
	WantedBy=multi-user.target" > "${sdcard_mount}/lib/systemd/system/firstboot.service"
	EOF

    ln -s "/lib/systemd/system/firstboot.service" \
       "${sdcard_mount}/etc/systemd/system/multi-user.target.wants/firstboot.service"
fi

umount_sdcard

new_name="${extracted_image%.*}-ssh-enabled.img"
mv "${extracted_image}" "${new_name}"

losetup --detach ${loop_base}
loop_base=""

echo ""
echo "Now you can burn the disk using something like:"
echo "      dd bs=4M status=progress if=${new_name} of=/dev/mmcblk????"
echo ""
