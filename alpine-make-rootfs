#!/bin/sh
# vim: set ts=4 sw=4:
#---help---
# Usage: alpine-make-rootfs [options] [--] <dest> [<script> [<script-opts...>]]
#
# This script creates Alpine Linux rootfs for containers. It must be run as
# root - to create files with correct permissions and use chroot (optional).
# If $APK is not available on the host system, then static apk-tools
# specified by $APK_TOOLS_URI is downloaded and used.
#
# Arguments:
#   <dest>                                Path where to write the rootfs. It may be:
#                                         - path with suffix .tar, .tar.bz2, .tbz, .tar.gz, .tgz,
#                                           or tar.xz to create a TAR archive;
#                                         - other path to keep rootfs as a directory;
#                                         - or "-" to dump TAR archive (w/o compression) to STDOUT.
#
#   <script>                              Path of script to execute after installing base system in
#                                         the prepared rootfs and before clean-up. Use "-" to read
#                                         the script from STDIN; if it doesn't start with a shebang,
#                                         "#!/bin/sh -e" is prepended.
#
#   <script-opts>                         Arguments to pass to the script.
#
# Options and Environment Variables:
#   -b --branch ALPINE_BRANCH             Alpine branch to install; used only when
#                                         --repositories-file is not specified. Default is
#                                         latest-stable.
#
#   -s --fs-skel-dir FS_SKEL_DIR          Path of directory which content to recursively copy
#                                         (using rsync) into / of the rootfs.
#
#      --fs-skel-chown FS_SKEL_CHOWN      Force all files from FS_SKEL_DIR to be owned by the
#                                         specified USER:GROUP.
#
#      --keys-dir KEYS_DIR                Path of directory with Alpine keys to copy into
#                                         the rootfs. Default is /etc/apk/keys. If does not exist,
#                                         keys for x86_64 embedded in this script will be used.
#
#   -m --mirror-uri ALPINE_MIRROR         URI of the Aports mirror to fetch packages; used only
#                                         when --repositories-file is not specified. Default is
#                                         http://dl-cdn.alpinelinux.org/alpine.
#
#   -C --no-cleanup (CLEANUP)             Don't umount and remove temporary directories when done.
#
#      --no-default-pkgs (DEFAULT_PKGS)   Don't install the default base packages (alpine-baselayout
#                                         busybox busybox-suid musl-utils), i.e. only the packages
#                                         specified in --packages will be installed. Use only if
#                                         you know what are you doing!
#
#   -p --packages PACKAGES                Additional packages to install into the rootfs.
#
#   -r --repositories-file REPOS_FILE     Path of repositories file to copy into the rootfs.
#                                         If not specified, a repositories file will be created with
#                                         Alpine's main and community repositories on --mirror-uri.
#
#   -c --script-chroot (SCRIPT_CHROOT)    Bind <script>'s directory (or CWD if read from STDIN) at
#                                         /mnt inside the rootfs dir and chroot into the rootfs
#                                         before executing <script>. Otherwise <script> is executed
#                                         in the current directory and $ROOTFS variable points to
#                                         the rootfs directory.
#
#   -d --temp-dir TEMP_DIR                Path where to create a temporary directory; used for
#                                         downloading apk-tools when not available on the host
#                                         sytem or for rootfs when <dest> is "-" (i.e. STDOUT).
#                                         This path must not exist! Defaults to using `mkdir -d`.
#
#   -t --timezone TIMEZONE                Timezone to set (e.g. Europe/Prague). Default is to leave
#                                         timezone UTC.
#
#   -h --help                             Show this help message and exit.
#
#   -v --version                          Print version and exit.
#
#   APK                                   APK command to use. Default is "apk".
#
#   APK_OPTS                              Options to pass into apk on each execution.
#                                         Default is "--no-progress".
#
#   APK_TOOLS_URI                         URL of apk-tools binary to download if $APK is not found
#                                         on the host system. Default is x86_64 apk.static from
#                                         https://gitlab.alpinelinux.org/alpine/apk-tools/-/packages.
#
#   APK_TOOLS_SHA256                      SHA-256 checksum of $APK_TOOLS_URI.
#
# Each option can be also provided by environment variable. If both option and
# variable is specified and the option accepts only one argument, then the
# option takes precedence.
#
# https://github.com/alpinelinux/alpine-make-rootfs
#---help---
set -eu

readonly PROGNAME='alpine-make-rootfs'
readonly VERSION='0.7.0'

# Base Alpine packages to install in rootfs.
readonly ALPINE_BASE_PKGS='alpine-baselayout busybox busybox-suid musl-utils'

# Alpine APK keys for verification of packages for x86_64.
readonly ALPINE_KEYS='
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1yHJxQgsHQREclQu4Ohe\nqxTxd1tHcNnvnQTu/UrTky8wWvgXT+jpveroeWWnzmsYlDI93eLI2ORakxb3gA2O\nQ0Ry4ws8vhaxLQGC74uQR5+/yYrLuTKydFzuPaS1dK19qJPXB8GMdmFOijnXX4SA\njixuHLe1WW7kZVtjL7nufvpXkWBGjsfrvskdNA/5MfxAeBbqPgaq0QMEfxMAn6/R\nL5kNepi/Vr4S39Xvf2DzWkTLEK8pcnjNkt9/aafhWqFVW7m3HCAII6h/qlQNQKSo\nGuH34Q8GsFG30izUENV9avY7hSLq7nggsvknlNBZtFUcmGoQrtx3FmyYsIC8/R+B\nywIDAQAB
alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlzMkl7b5PBdfMzGdCT0\ncGloRr5xGgVmsdq5EtJvFkFAiN8Ac9MCFy/vAFmS8/7ZaGOXoCDWbYVLTLOO2qtX\nyHRl+7fJVh2N6qrDDFPmdgCi8NaE+3rITWXGrrQ1spJ0B6HIzTDNEjRKnD4xyg4j\ng01FMcJTU6E+V2JBY45CKN9dWr1JDM/nei/Pf0byBJlMp/mSSfjodykmz4Oe13xB\nCa1WTwgFykKYthoLGYrmo+LKIGpMoeEbY1kuUe04UiDe47l6Oggwnl+8XD1MeRWY\nsWgj8sF4dTcSfCMavK4zHRFFQbGp/YFJ/Ww6U9lA3Vq0wyEI6MCMQnoSMFwrbgZw\nwwIDAQAB
alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub:MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAutQkua2CAig4VFSJ7v54\nALyu/J1WB3oni7qwCZD3veURw7HxpNAj9hR+S5N/pNeZgubQvJWyaPuQDm7PTs1+\ntFGiYNfAsiibX6Rv0wci3M+z2XEVAeR9Vzg6v4qoofDyoTbovn2LztaNEjTkB+oK\ntlvpNhg1zhou0jDVYFniEXvzjckxswHVb8cT0OMTKHALyLPrPOJzVtM9C1ew2Nnc\n3848xLiApMu3NBk0JqfcS3Bo5Y2b1FRVBvdt+2gFoKZix1MnZdAEZ8xQzL/a0YS5\nHd0wj5+EEKHfOd3A75uPa/WQmA+o0cBFfrzm69QDcSJSwGpzWrD1ScH3AK8nWvoj\nv7e9gukK/9yl1b4fQQ00vttwJPSgm9EnfPHLAtgXkRloI27H6/PuLoNvSAMQwuCD\nhQRlyGLPBETKkHeodfLoULjhDi1K2gKJTMhtbnUcAA7nEphkMhPWkBpgFdrH+5z4\nLxy+3ek0cqcI7K68EtrffU8jtUj9LFTUC8dERaIBs7NgQ/LfDbDfGh9g6qVj1hZl\nk9aaIPTm/xsi8v3u+0qaq7KzIBc9s59JOoA8TlpOaYdVgSQhHHLBaahOuAigH+VI\nisbC9vmqsThF2QdDtQt37keuqoda2E6sL7PUvIyVXDRfwX7uMDjlzTxHTymvq2Ck\nhtBqojBnThmjJQFgZXocHG8CAwEAAQ==
'
# List of directories to remove when empty.
readonly UNNECESSARY_DIRS='
	/home /media/cdrom /media/floppy /media/usb /mnt /srv /usr/local/bin
	/usr/local/lib /usr/local/share
'
# An opaque string used to detect changes in resolv.conf.
readonly RESOLVCONF_MARK="### created by $PROGNAME ###"
# Name used as a "virtual package" for temporarily installed packages.
readonly VIRTUAL_PKG=".make-$PROGNAME"

: ${APK:="apk"}
: ${APK_OPTS:="--no-progress"}
: ${APK_TOOLS_URI:="https://gitlab.alpinelinux.org/api/v4/projects/5/packages/generic/v2.14.0/x86_64/apk.static"}
: ${APK_TOOLS_SHA256:="1c65115a425d049590bec7c729c7fd88357fbb090a6fc8c31d834d7b0bc7d6f2"}


# Set pipefail if supported.
if ( set -o pipefail 2>/dev/null ); then
	set -o pipefail
fi

# For compatibility with systems that does not have "realpath" command.
if ! command -v realpath >/dev/null; then
	alias realpath='readlink -f'
fi

die() {
	printf '\033[1;31mERROR:\033[0m %s\n' "$@" >&2  # bold red
	exit 1
}

einfo() {
	printf '\n\033[1;36m> %s\033[0m\n' "$@" >&2  # bold cyan
}

# Prints help and exists with the specified status.
help() {
	sed -En '/^#---help---/,/^#---help---/p' "$0" | sed -E 's/^# ?//; 1d;$d;'
	exit ${1:-0}
}

# Cleans the host system. This function is executed before exiting the script.
cleanup() {
	set +eu
	trap '' EXIT HUP INT TERM  # unset trap to avoid loop

	if [ "$INSTALL_HOST_PKGS" = yes ] && _apk info --quiet --installed $VIRTUAL_PKG; then
		_apk del $VIRTUAL_PKG >&2
	fi
	if [ -d "$TEMP_DIR" ]; then
		rm -Rf "$TEMP_DIR"
	fi
	if [ -d "$rootfs" ]; then
		umount_recursively "$rootfs" \
			|| die "Failed to unmount mounts inside $rootfs!"
		[ "$rootfs" = "$ROOTFS_DEST" ] || rm -Rf "$rootfs"
	fi
}

_apk() {
	"$APK" $APK_OPTS "$@"
}

# Writes Alpine APK keys embedded in this script into directory $1.
dump_alpine_keys() {
	local dest_dir="$1"
	local content file line

	mkdir -p "$dest_dir"
	for line in $ALPINE_KEYS; do
		file=${line%%:*}
		content=${line#*:}

		printf -- "-----BEGIN PUBLIC KEY-----\n$content\n-----END PUBLIC KEY-----\n" \
			> "$dest_dir/$file"
	done
}

# Binds the directory $1 at the mountpoint $2 and sets propagation to private.
mount_bind() {
	mkdir -p "$2"
	mount --bind "$1" "$2"
	mount --make-private "$2"
}

# Prepares chroot at the specified path.
prepare_chroot() {
	local dest="$1"

	mkdir -p "$dest"/proc
	mount -t proc none "$dest"/proc
	mount_bind /dev "$dest"/dev
	mount_bind /sys "$dest"/sys

	install -D -m 644 /etc/resolv.conf "$dest"/etc/resolv.conf
	echo "$RESOLVCONF_MARK" >> "$dest"/etc/resolv.conf
}

# Sets up timezone $1 in Alpine rootfs.
setup_timezone() {
	local timezone="$1"
	local rootfs="${2:-}"

	_apk add --root "$rootfs" tzdata

	install -D "$rootfs"/usr/share/zoneinfo/$timezone \
		"$rootfs"/etc/zoneinfo/$timezone
	ln -sf zoneinfo/$timezone "$rootfs"/etc/localtime

	_apk del --root "$rootfs" tzdata
}

# Unmounts all filesystems under the directory tree $1 (must be absolute path).
umount_recursively() {
	local mount_point="$(realpath "$1")"

	cat /proc/mounts \
		| cut -d ' ' -f 2 \
		| { grep "^$mount_point/" || true; } \
		| sort -r \
		| xargs -r -n 1 umount
}

# Downloads the specified file using wget and checks checksum.
wgets() (
	local url="$1"
	local sha256="$2"
	local dest="${3:-.}"

	cd "$dest" \
		&& wget -T 10 --no-verbose "$url" \
		&& echo "$sha256  ${url##*/}" | sha256sum -c
)

# Writes STDIN into file $1 and sets it executable bit. If the content does not
# start with a shebang, prepends "#!/bin/sh -e" before the first line.
write_script() {
	local filename="$1"

	cat > "$filename.tmp"

	if ! grep -q -m 1 '^#!' "$filename.tmp"; then
		echo "#!/bin/sh -e" > "$filename"
	fi

	cat "$filename.tmp" >> "$filename"
	rm "$filename.tmp"

	chmod +x "$filename"
}


#=============================  M a i n  ==============================#

opts=$(getopt -n $PROGNAME -o b:m:Cp:r:s:cd:t:hV \
	-l branch:,fs-skel-chown:,fs-skel-dir:,keys-dir:,mirror-uri:,no-cleanup,no-default-pkgs,packages:,repositories-file:,script-chroot,temp-dir:,timezone:,help,version \
	-- "$@") || help 1 >&2

eval set -- "$opts"
while [ $# -gt 0 ]; do
	n=2
	case "$1" in
		-b | --branch) ALPINE_BRANCH="$2";;
		-s | --fs-skel-dir) FS_SKEL_DIR="$2";;
		     --fs-skel-chown) FS_SKEL_CHOWN="$2";;
		     --keys-dir) KEYS_DIR="$2";;
		-m | --mirror-uri) ALPINE_MIRROR="$2";;
		-C | --no-cleanup) CLEANUP='no'; n=1;;
		     --no-default-pkgs) DEFAULT_PKGS='no'; n=1;;
		-p | --packages) PACKAGES="${PACKAGES:-} $2";;
		-r | --repositories-file) REPOS_FILE="$2";;
		-c | --script-chroot) SCRIPT_CHROOT='yes'; n=1;;
		-d | --temp-dir) TEMP_DIR="$2";;
		-t | --timezone) TIMEZONE="$2";;
		-h | --help) help 0;;
		-V | --version) echo "$PROGNAME $VERSION"; exit 0;;
		--) shift; break;;
	esac
	shift $n
done

[ $# -ne 0 ] || help 1 >&2

ROOTFS_DEST="$1"; shift
SCRIPT=
[ $# -eq 0 ] || { SCRIPT="$1"; shift; }

[ "$(id -u)" -eq 0 ] || die 'This script must be run as root!'
[ ! -e "${TEMP_DIR:-}" ] || die "Temp path $TEMP_DIR must not exist!"

: ${ALPINE_BRANCH:="latest-stable"}
: ${ALPINE_MIRROR:="http://dl-cdn.alpinelinux.org/alpine"}
: ${CLEANUP:="yes"}
: ${DEFAULT_PKGS:="yes"}
: ${FS_SKEL_CHOWN:=}
: ${FS_SKEL_DIR:=}
: ${KEYS_DIR:="/etc/apk/keys"}
: ${PACKAGES:=}
: ${REPOS_FILE:=}
: ${SCRIPT_CHROOT:="no"}
: ${TEMP_DIR:="$(mktemp -d /tmp/$PROGNAME.XXXXXX)"}
: ${TIMEZONE:=}

case "$ALPINE_BRANCH" in
	[0-9]*) ALPINE_BRANCH="v$ALPINE_BRANCH";;
esac

host_pkgs=''
case "$ROOTFS_DEST" in
	*.tar.bz2 | *.tbz) tar_opts='-cj';;
	*.tar.gz | *.tgz) tar_opts='-cz';;
	*.tar.xz) tar_opts='-cJ'; host_pkgs="$host_pkgs xz";;
	*.tar | -) tar_opts='-c';;
	*) tar_opts='';;
esac
[ -z "$FS_SKEL_DIR" ] || host_pkgs="$host_pkgs rsync"

[ "$PACKAGES" ] || [ "$DEFAULT_PKGS" = 'yes' ] || \
	die 'No packages specified to be installed!'

rootfs="$ROOTFS_DEST"
if [ "$ROOTFS_DEST" = '-' ]; then
	rootfs="$TEMP_DIR/rootfs"
elif [ "$tar_opts" ]; then
	rootfs="${rootfs%.*}"
	rootfs="${rootfs%.tar}"
fi

script_file="$SCRIPT"
if [ "$SCRIPT" = '-' ]; then
	script_file="$TEMP_DIR/.setup.sh"
	write_script "$script_file"
fi
if [ "$script_file" ]; then
	script_file=$(realpath "$script_file")
fi

if [ -f /etc/alpine-release ]; then
	: ${INSTALL_HOST_PKGS:="yes"}
else
	: ${INSTALL_HOST_PKGS:="no"}
fi

[ "$CLEANUP" = no ] || trap cleanup EXIT HUP INT TERM

#-----------------------------------------------------------------------
if [ "$INSTALL_HOST_PKGS" = yes ] && [ "$host_pkgs" ]; then
	einfo "Installing $host_pkgs on host system"
	_apk add -t $VIRTUAL_PKG $host_pkgs >&2
fi

#-----------------------------------------------------------------------
if ! command -v "$APK" >/dev/null; then
	einfo "$APK not found, downloading static apk-tools"

	wgets "$APK_TOOLS_URI" "$APK_TOOLS_SHA256" "$TEMP_DIR"
	APK="$TEMP_DIR/apk.static"
	chmod +x "$APK"
fi

#-----------------------------------------------------------------------
einfo 'Installing system'

mkdir -p "$rootfs"/etc/apk/keys

if [ -f "$REPOS_FILE" ]; then
	install -m 644 "$REPOS_FILE" "$rootfs"/etc/apk/repositories
else
	cat > "$rootfs"/etc/apk/repositories <<-EOF
		$ALPINE_MIRROR/$ALPINE_BRANCH/main
		$ALPINE_MIRROR/$ALPINE_BRANCH/community
	EOF
fi

if [ -d "$KEYS_DIR" ]; then
	cp "$KEYS_DIR"/* "$rootfs"/etc/apk/keys/
else
	dump_alpine_keys "$rootfs"/etc/apk/keys/
fi

if [ "$DEFAULT_PKGS" = 'yes' ]; then
	_apk add --root "$rootfs" --initdb $ALPINE_BASE_PKGS >&2
fi
_apk add --root "$rootfs" --initdb $PACKAGES >&2

if ! [ -f "$rootfs"/etc/alpine-release ]; then
	if _apk info --root "$rootfs" --quiet alpine-release >/dev/null; then
		_apk add --root "$rootfs" alpine-release
	else
		# In Alpine <3.17, this package contains /etc/os-release,
		# /etc/alpine-release and /etc/issue, but we don't wanna install all
		# its dependencies (e.g. openrc).
		_apk fetch --root "$rootfs" --stdout alpine-base \
			| tar -xz -C "$rootfs" etc >&2
	fi
fi

# Disable root log in without password.
sed -i 's/^root::/root:*:/' "$rootfs"/etc/shadow

[ -e "$rootfs"/var/run ] || ln -s /run "$rootfs"/var/run

#-----------------------------------------------------------------------
if [ "$TIMEZONE" ]; then
	einfo "Setting timezone $TIMEZONE"
	setup_timezone "$TIMEZONE" "$rootfs" >&2
fi

#-----------------------------------------------------------------------
if [ "$FS_SKEL_DIR" ]; then
	einfo "Copying content of $FS_SKEL_DIR into rootfs"

	[ "$FS_SKEL_CHOWN" ] \
		&& rsync_opts="--chown $FS_SKEL_CHOWN" \
		|| rsync_opts='--numeric-ids'
	rsync --archive --info=NAME2 --whole-file $rsync_opts "$FS_SKEL_DIR"/ "$rootfs"/ >&2

	# rsync may modify perms of the rootfs dir itself, so make sure it's correct.
	install -d -m 0755 -o root -g root "$rootfs"
fi

#-----------------------------------------------------------------------
if [ "$SCRIPT" ]; then
	script_name="${script_file##*/}"

	if [ "$SCRIPT_CHROOT" = 'no' ]; then
		einfo "Executing script: $script_name $*"

		ROOTFS="$rootfs" "$script_file" "$@" >&2 || die 'Script failed'
	else
		einfo 'Preparing chroot'

		_apk add --root "$rootfs" -t "$VIRTUAL_PKG" apk-tools >&2
		prepare_chroot "$rootfs"

		if [ "$SCRIPT" = '-' ]; then
			cp "$script_file" "$rootfs/$script_name"
			bind_dir="$(pwd)"
			script_file2="/$script_name"
		else
			bind_dir="$(dirname "$script_file")"
			script_file2="./$script_name"
		fi
		echo "Mounting $bind_dir to /mnt inside chroot" >&2
		mount_bind "$bind_dir" "$rootfs"/mnt

		einfo "Executing script in chroot: $script_name $*"

		chroot "$rootfs" \
			/bin/sh -c "cd /mnt && $script_file2 \"\$@\"" -- "$@" >&2 \
			|| die 'Script failed'

		[ "$SCRIPT" = '-' ] && rm -f "$rootfs/$script_name"
		umount_recursively "$rootfs"
	fi
fi

#-----------------------------------------------------------------------
einfo 'Cleaning-up rootfs'

if _apk info --root "$rootfs" --quiet --installed "$VIRTUAL_PKG"; then
	_apk del --root "$rootfs" --purge "$VIRTUAL_PKG" >&2
fi

if grep -qw "$RESOLVCONF_MARK" "$rootfs"/etc/resolv.conf 2>/dev/null; then
	rm "$rootfs"/etc/resolv.conf
fi

rm -Rf "$rootfs"/dev/*

if [ -f "$rootfs"/sbin/apk ]; then
	rm -Rf "$rootfs"/var/cache/apk/*
else
	rm -Rf "$rootfs"/etc/apk "$rootfs"/lib/apk "$rootfs"/var/cache/apk
fi

for dir in $UNNECESSARY_DIRS; do
	rmdir -p "$rootfs$dir" 2>/dev/null || true
done

#-----------------------------------------------------------------------
if [ "$tar_opts" ]; then
	einfo 'Creating rootfs archive'

	tar -C "$rootfs" $tar_opts --numeric-owner -f "$ROOTFS_DEST" .

	if [ -f "$ROOTFS_DEST" ] && [ "${SUDO_UID:-}" ] && [ "${SUDO_GID:-}" ]; then
		chown "$SUDO_UID:$SUDO_GID" "$ROOTFS_DEST"
	fi

	ls -la "$ROOTFS_DEST" >&2
fi
