#!/bin/sh
# php2shell-check.sh
# Detect PHP builds affected by CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell").
# Fixed upstream in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (released 2026-10-21).
#
# Step 1 checks whether PHP is installed at all (commands, packages, panel PHP
# directories, running processes, Apache modules). If not, it says so and exits 0.
# Step 2 checks every PHP build found against the fixed versions.
# Step 3 lists the websites served by each PHP build (cPanel, Plesk, DirectAdmin,
# CyberPanel/OpenLiteSpeed, HestiaCP natively; other servers via web-server
# vhosts and PHP-FPM pools).
#
# Read-only: runs "<php> -v" (plus one ini_get for CLI builds) on the host, reads
# /proc and queries the package manager. Nothing on the server is changed.
#
# Containers (Docker, Podman, containerd/Kubernetes, LXC) are checked passively:
# PHP processes running inside containers are always detected through /proc, and
# their version is read from the binary file itself. Nothing is executed inside a
# container, and no container or image is started, stopped, pulled or modified.
#
# Portable POSIX sh (bash, dash, ash/busybox). Covers distro PHP, Ondrej/Sury,
# Remi, cPanel ea-php, CloudLinux alt-php, Plesk, DirectAdmin, CyberPanel /
# OpenLiteSpeed lsphp, CWP, HestiaCP/VestaCP, CloudPanel, aaPanel, Webuzo,
# ISPConfig, ISPmanager, Virtualmin, InterWorx, Apache mod_php and any running
# PHP process. Run as root for full coverage.
#
# Usage: sh php2shell-check.sh [--csv] [--deep] [--containers] [--images] [--no-color]
#   --csv         one row per finding, for collecting results across servers
#   --deep        also search the root filesystem for custom PHP builds (slower)
#   --containers  also scan the filesystem of every running Docker/Podman container
#                 for installed-but-idle PHP, and check stopped containers
#   --images      also check local Docker/Podman images (via image metadata only)
#   --no-sites    skip step 3 (listing websites by the PHP version serving them)
#   --no-color    plain text output
#
# Exit codes: 0 = no affected build found
#             1 = affected build found, or a process still runs a replaced binary
#             2 = only items needing review (EOL, CHECK-VENDOR, UNKNOWN, NOT-LISTED)

FIXED_82=8.2.35
FIXED_83=8.3.36
FIXED_84=8.4.27
FIXED_85=8.5.12

CSV=0; DEEP=0; CONT=0; IMG=0; SITES=1; COLOR=1

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; }

for a in "$@"; do
  case $a in
    --csv) CSV=1; COLOR=0 ;;
    --deep) DEEP=1 ;;
    --containers) CONT=1 ;;
    --images) IMG=1 ;;
    --no-sites) SITES=0 ;;
    --no-color) COLOR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $a (try --help)" >&2; exit 64 ;;
  esac
done

[ -t 1 ] || COLOR=0
if [ "$COLOR" = 1 ]; then
  R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
  B=$(printf '\033[1m'); N=$(printf '\033[0m')
else
  R=; G=; Y=; B=; N=
fi

TMP=$(mktemp -d 2>/dev/null) || { TMP=/tmp/php2shell.$$; mkdir -p "$TMP" || exit 70; }
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM
for f in seen running deleted mods rows cproc cmods cseen cnames selcache srows; do : >"$TMP/$f"; done

if command -v timeout >/dev/null 2>&1; then TO="timeout 15"; else TO=""; fi

[ "$(id -u 2>/dev/null)" = 0 ] || [ "$CSV" = 1 ] || \
  echo "${Y}Note: not running as root - other users' processes and some paths will be missed.${N}" >&2

# ---------------------------------------------------------------- helpers
rp() { readlink -f "$1" 2>/dev/null || echo "$1"; }

add_cand() {
  [ -f "$1" ] && [ -x "$1" ] || return 0
  _r=$(rp "$1")
  grep -Fxq "$_r" "$TMP/seen" 2>/dev/null || echo "$_r" >>"$TMP/seen"
}

# Upstream version string compiled into any PHP binary or libphp module.
embedded_ver() {
  grep -aoE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$1" 2>/dev/null | head -n 1 | sed 's/.*PHP\///'
}

pkg_of() {   # prints "name version" of the package owning $1, or nothing
  if command -v dpkg-query >/dev/null 2>&1; then
    _pk=$(dpkg-query -S "$1" 2>/dev/null | head -n 1 | cut -d: -f1)
    if [ -n "$_pk" ]; then echo "$_pk $(dpkg-query -W -f='${Version}' "$_pk" 2>/dev/null)"; return; fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    _o=$(rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n 1)
    if [ -n "$_o" ]; then echo "$_o"; return; fi
  fi
  if command -v apk >/dev/null 2>&1; then
    _o=$(apk info --who-owns "$1" 2>/dev/null | awk '{print $NF}')
    [ -n "$_o" ] && echo "$_o -"
  fi
}

# Distro builds (Ubuntu/Debian archive, RHEL AppStream, SUSE, TuxCare ELS) often
# backport security fixes without changing the upstream version number.
is_backport() {   # $1 = package name, $2 = package version
  case $1 in
    ea-php*|alt-php*|plesk-php*|lsphp*|php[0-9][0-9]-php*|sw-engine*) return 1 ;;
  esac
  case $2 in
    ""|-) return 1 ;;
    *+debian*|*+ubuntu*|*gbp*|*remi*|*cpanel*) return 1 ;;
    *tuxcare*|*.els*|*els[0-9]*) return 0 ;;
    *ubuntu*|*deb[0-9]*u[0-9]*|*~deb*) return 0 ;;
    *.el[0-9]*|*module+el*|*amzn*|*suse*|*lp15*|*.fc[0-9]*) return 0 ;;
  esac
  return 1
}

fixed_for() {
  case $1 in
    8.2.*) echo $FIXED_82 ;; 8.3.*) echo $FIXED_83 ;;
    8.4.*) echo $FIXED_84 ;; 8.5.*) echo $FIXED_85 ;; *) echo - ;;
  esac
}

classify() {   # $1 = x.y.z, $2 = pkg name, $3 = pkg version
  case $1 in [0-9]*.[0-9]*.[0-9]*) ;; *) echo UNKNOWN; return ;; esac
  _maj=${1%%.*}; _rest=${1#*.}; _min=${_rest%%.*}; _pat=${_rest#*.}; _pat=${_pat%%[!0-9]*}
  _fix=$(fixed_for "$1")
  if [ "$_fix" = - ]; then
    if [ "$_maj" -lt 8 ] || { [ "$_maj" -eq 8 ] && [ "$_min" -lt 2 ]; }; then echo EOL; else echo NOT-LISTED; fi
    return
  fi
  _fp=${_fix##*.}
  if [ "${_pat:-0}" -ge "$_fp" ]; then echo PATCHED
  elif is_backport "$2" "$3"; then echo CHECK-VENDOR
  else echo VULNERABLE
  fi
}

sev() {
  case $1 in
    VULNERABLE) echo 1 ;; CHECK-VENDOR) echo 2 ;; EOL) echo 3 ;;
    UNKNOWN) echo 4 ;; NOT-LISTED) echo 5 ;; *) echo 6 ;;
  esac
}

emit() {   # status version sapi binary running package upload_progress
  echo "$(sev "$1")|$1|$2|$3|$(fixed_for "$2")|$5|$4|$6|$7" >>"$TMP/rows"
}

detect_panel() {
  _p=""
  [ -x /usr/local/cpanel/cpanel ] && _p="$_p cPanel"
  [ -d /usr/local/psa ] && _p="$_p Plesk"
  [ -d /usr/local/directadmin ] && _p="$_p DirectAdmin"
  [ -d /usr/local/CyberCP ] && _p="$_p CyberPanel"
  [ -d /usr/local/hestia ] && _p="$_p HestiaCP"
  [ -d /usr/local/vesta ] && _p="$_p VestaCP"
  [ -d /usr/local/cwpsrv ] && _p="$_p CWP"
  [ -x /usr/bin/clpctl ] && _p="$_p CloudPanel"
  [ -d /www/server/panel ] && _p="$_p aaPanel"
  [ -d /usr/local/webuzo ] && _p="$_p Webuzo"
  [ -d /usr/local/ispconfig ] && _p="$_p ISPConfig"
  [ -d /usr/local/mgr5 ] && _p="$_p ISPmanager"
  { [ -d /usr/share/webmin/virtual-server ] || [ -d /usr/libexec/webmin/virtual-server ]; } && _p="$_p Virtualmin"
  [ -d /usr/local/interworx ] && _p="$_p InterWorx"
  [ -d /usr/local/lsws ] && _p="$_p LiteSpeed"
  { [ -f /etc/cloudlinux-release ] || grep -qi cloudlinux /etc/redhat-release 2>/dev/null; } && _p="$_p CloudLinux"
  _p=${_p# }
  echo "${_p:-none detected}"
}

csvq() { printf '"%s"' "$(echo "$1" | sed 's/"/""/g')"; }

# ---------------------------------------------------------------- container helpers
# All passive: read /proc and files, plus read-only "ps"/"inspect" API calls.
HOST_NS=$(readlink "/proc/$$/ns/mnt" 2>/dev/null)

in_container() {   # $1 = pid; true if the process lives in another mount namespace
  [ -n "$HOST_NS" ] || return 1
  _ns=$(readlink "/proc/$1/ns/mnt" 2>/dev/null) || return 1
  [ "$_ns" != "$HOST_NS" ]
}

cid_of() {   # container id from the cgroup path (Docker, Podman, containerd, CRI-O)
  _c=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | tail -n 1)
  [ -n "$_c" ] && { echo "$_c"; return; }
  echo "ns:$(readlink "/proc/$1/ns/mnt" 2>/dev/null | tr -dc '0-9')"
}

CNAMES_DONE=0
load_cnames() {
  [ "$CNAMES_DONE" = 1 ] && return; CNAMES_DONE=1
  for _e in docker podman; do
    command -v "$_e" >/dev/null 2>&1 || continue
    $TO "$_e" ps -a --no-trunc --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null >>"$TMP/cnames"
  done
}

cname() {   # $1 = container id -> "name (image)" or short id
  load_cnames
  _n=$(awk -v i="$1" '$1==i {print $2 " (" $3 ")"; exit}' "$TMP/cnames")
  [ -n "$_n" ] && { echo "$_n"; return; }
  case $1 in ns:*) echo "$1" ;; *) echo "$1" | cut -c1-12 ;; esac
}

# Resolve symlinks inside a container root without escaping to the host root.
croot_resolve() {   # $1 = root, $2 = path inside root
  _p=$2; _i=0
  while [ -L "$1$_p" ] && [ "$_i" -lt 20 ]; do
    _t=$(readlink "$1$_p")
    case $_t in /*) _p=$_t ;; *) _p="${_p%/*}/$_t" ;; esac
    _i=$((_i + 1))
  done
  echo "$_p"
}

pkg_in_root() {   # $1 = container root, $2 = path inside it -> "name version"
  if [ -d "$1/var/lib/dpkg/info" ]; then
    _l=$(grep -lxF "$2" "$1"/var/lib/dpkg/info/*.list 2>/dev/null | head -n 1)
    [ -n "$_l" ] || return 0
    _pk=${_l##*/}; _pk=${_pk%.list}; _pk=${_pk%%:*}
    _v=$(awk -v p="$_pk" '$1=="Package:"{f=($2==p)} f && $1=="Version:"{print $2; exit}' "$1/var/lib/dpkg/status" 2>/dev/null)
    echo "$_pk $_v"
  elif [ -f "$1/lib/apk/db/installed" ]; then
    awk -v f="${2#/}" 'BEGIN{n=split(f,a,"/"); b=a[n]; d=substr(f,1,length(f)-length(b)-1)}
      /^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^F:/{cd=substr($0,3)}
      /^R:/{ if (cd==d && substr($0,3)==b) {print p " " v; exit} }' "$1/lib/apk/db/installed"
  fi
}

sapi_from_name() {
  case ${1##*/} in
    php-fpm*) echo fpm-fcgi ;; lsphp*) echo litespeed ;; php-cgi*) echo cgi-fcgi ;;
    libphp*) echo apache2handler ;; *) echo cli ;;
  esac
}

# Report one PHP binary/module found inside a container (no execution).
container_emit() {   # $1 = cid, $2 = file to read (host view), $3 = path inside container, $4 = root, $5 = running
  _key="$1|$3"
  grep -Fxq "$_key" "$TMP/cseen" && return 0
  echo "$_key" >>"$TMP/cseen"
  _v=$(embedded_ver "$2")
  [ -n "$_v" ] || case ${3##*/} in php|php[0-9]*|php-fpm*|php-cgi*|lsphp*|libphp*) ;; *) return 0 ;; esac
  _pkg=$(pkg_in_root "$4" "$3")
  _pn=$(echo "$_pkg" | awk '{print $1}'); _pv=$(echo "$_pkg" | awk '{print $2}')
  emit "$(classify "$_v" "$_pn" "$_pv")" "${_v:-?}" "$(sapi_from_name "$3")" \
       "container $(cname "$1"): $3" "$5" "$_pkg" "-"
}

HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)
OS=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )
PANEL=$(detect_panel)

if [ "$CSV" = 0 ]; then
  echo "${B}PHP2Shell check (CVE-2026-109618 / CVE-2026-109619)${N}"
  echo "Host:   $HOST"
  echo "OS:     $OS"
  echo "Panel:  $PANEL"
  echo "Fixed:  $FIXED_85 / $FIXED_84 / $FIXED_83 / $FIXED_82"
  echo
fi

# ---------------------------------------------------------------- step 1: is PHP installed?
PRE="$TMP/pre"; : >"$PRE"

# a) PHP commands on PATH
for b in php php-fpm php-cgi lsphp; do
  _c=$(command -v "$b" 2>/dev/null) && echo "command   $_c" >>"$PRE"
done

# b) Installed PHP packages (only those that provide a PHP runtime)
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Status}|${Package}|${Version}\n' 2>/dev/null \
    | awk -F'|' '$1 ~ /installed$/ && $2 ~ /^(php[0-9.]*(-cli|-fpm|-cgi)?|libapache2-mod-php[0-9.]*|lsphp[0-9]+|ea-php[0-9]+-php-(cli|fpm)|sw-engine)$/ {print "package   " $2 " " $3}' >>"$PRE"
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null \
    | grep -E '^(php(-cli|-fpm)?|php[0-9]+-php-(cli|fpm)|ea-php[0-9]+-php-(cli|fpm)|alt-php[0-9]+-(cli|fpm)|lsphp[0-9]+|plesk-php[0-9]+-(cli|fpm)|sw-engine) ' \
    | sed 's/^/package   /' >>"$PRE"
fi
if command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | grep -E '^php[0-9]*(-cli|-fpm)?-[0-9]' | sed 's/^/package   /' >>"$PRE"
fi

# c) Control-panel / third-party PHP install directories
for d in /opt/cpanel/ea-php[0-9]* /opt/alt/php[0-9]* /opt/alt/php-fpm[0-9]* /opt/plesk/php/[0-9]* \
         /usr/local/php[0-9]* /usr/local/php /usr/local/lsws/lsphp[0-9]* /opt/remi/php[0-9]* \
         /www/server/php/[0-9]* /usr/local/apps/php[0-9]* /opt/php[0-9]*; do
  [ -d "$d" ] && echo "directory $d" >>"$PRE"
done

# d) Running PHP processes
for d in /proc/[0-9]*; do
  _e=$(readlink "$d/exe" 2>/dev/null) || continue
  case ${_e##*/} in php*|lsphp*|sw-engine*) ;; *) continue ;; esac
  if in_container "${d#/proc/}"; then echo "process   [container] ${_e% (deleted)}"
  else echo "process   ${_e% (deleted)}"; fi
done | sort -u >>"$PRE"
for m in /proc/[0-9]*/maps; do
  grep -q libphp "$m" 2>/dev/null || continue
  _pid=${m#/proc/}; _pid=${_pid%/maps}
  if in_container "$_pid"; then echo "module    [container] mod_php loaded (pid $_pid)"; fi
done | head -n 1 >>"$PRE"

# e) Apache mod_php modules
for m in /usr/lib/apache2/modules/libphp*.so /usr/lib*/httpd/modules/libphp*.so \
         /etc/httpd/modules/libphp*.so /usr/local/apache/modules/libphp*.so; do
  [ -f "$m" ] && echo "module    $m" >>"$PRE"
done

if [ ! -s "$PRE" ]; then
  if [ "$DEEP" = 0 ] && [ "$CONT" = 0 ] && [ "$IMG" = 0 ]; then
    if [ "$CSV" = 1 ]; then
      echo "host,os,panel,status,version,sapi,fixed_in,running,binary,package,upload_progress_cli,website"
      printf '%s,%s,%s,NOT-INSTALLED,,,,,,,,\n' "$(csvq "$HOST")" "$(csvq "$OS")" "$(csvq "$PANEL")"
    else
      echo "${G}Step 1: PHP is not installed on this server - nothing to check.${N}"
      echo "(No PHP commands, packages, panel PHP directories, processes or Apache modules found."
      echo " Use --deep to search the whole filesystem, or --containers / --images for"
      echo " stopped Docker/Podman containers and local images.)"
    fi
    exit 0
  fi
  [ "$CSV" = 1 ] || echo "${Y}Step 1: no PHP found on the host - continuing because --deep/--containers/--images was given.${N}"
else
  if [ "$CSV" = 0 ]; then
    echo "${B}Step 1: PHP is installed${N} ($(grep -c . "$PRE") indicators found)"
    head -n 12 "$PRE" | sed 's/^/  /'
    [ "$(grep -c . "$PRE")" -gt 12 ] && echo "  ... and $(( $(grep -c . "$PRE") - 12 )) more"
  fi
fi
[ "$CSV" = 1 ] || { echo; echo "${B}Step 2: checking every PHP build against the fixed versions${N}"; echo; }

# ---------------------------------------------------------------- step 2: discovery
for p in \
  /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/bin/php-fpm* /usr/bin/lsphp* \
  /usr/sbin/php-fpm* /usr/local/bin/php /usr/local/bin/php[0-9]* /usr/local/sbin/php-fpm* \
  /usr/local/php*/bin/php /usr/local/php*/bin/php-cgi /usr/local/php*/sbin/php-fpm \
  /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/lsphp \
  /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
  /usr/local/cpanel/3rdparty/bin/php /usr/local/cpanel/3rdparty/php/*/bin/php \
  /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/bin/lsphp /opt/alt/php*/usr/sbin/php-fpm \
  /opt/alt/php-fpm*/usr/bin/php /opt/alt/php-fpm*/usr/sbin/php-fpm \
  /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /usr/bin/sw-engine /usr/sbin/sw-engine-fpm \
  /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/fcgi-bin/lsphp* \
  /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
  /www/server/php/*/bin/php /www/server/php/*/sbin/php-fpm \
  /usr/local/apps/php*/bin/php /usr/local/apps/php*/sbin/php-fpm \
  /opt/php*/bin/php /opt/php*/sbin/php-fpm \
  /usr/local/hestia/php/bin/php /usr/local/vesta/php/bin/php /usr/local/cwp/php*/bin/php
do add_cand "$p"; done

# Everything on $PATH
_oifs=$IFS; IFS=:
for d in $PATH; do
  IFS=$_oifs
  for p in "$d"/php "$d"/php[0-9]* "$d"/php-fpm* "$d"/php-cgi* "$d"/lsphp*; do add_cand "$p"; done
done
IFS=$_oifs

# Running processes: catches custom locations and binaries replaced on disk
# by an update while the old process keeps running.
for d in /proc/[0-9]*; do
  exe=$(readlink "$d/exe" 2>/dev/null) || continue
  case ${exe##*/} in php*|lsphp*|sw-engine*) ;; *) continue ;; esac
  # Processes inside containers are handled separately (their paths are not host paths)
  if in_container "${d#/proc/}"; then echo "${d#/proc/}|$exe" >>"$TMP/cproc"; continue; fi
  case $exe in
    *" (deleted)") echo "${exe% (deleted)}|${d#/proc/}" >>"$TMP/deleted" ;;
    *) add_cand "$exe"; rp "$exe" >>"$TMP/running" ;;
  esac
done

# Apache mod_php, loaded in memory or present on disk
: >"$TMP/mods_loaded"
for m in /proc/[0-9]*/maps; do
  grep -q 'libphp' "$m" 2>/dev/null || continue
  _pid=${m#/proc/}; _pid=${_pid%/maps}
  grep 'libphp' "$m" 2>/dev/null | awk '{p=""; for(i=6;i<=NF;i++) p=p (i>6?" ":"") $i; print p}' | sort -u >"$TMP/m1"
  if in_container "$_pid"; then
    sed "s/^/$_pid|/" "$TMP/m1" >>"$TMP/cmods"
  else
    cat "$TMP/m1" >>"$TMP/mods_loaded"
  fi
done
sort -u "$TMP/mods_loaded" -o "$TMP/mods_loaded"
while IFS= read -r m; do
  case $m in
    *" (deleted)") echo "${m% (deleted)}|apache (mod_php)" >>"$TMP/deleted" ;;
    *) rp "$m" >>"$TMP/mods" ;;
  esac
done <"$TMP/mods_loaded"
for m in /usr/lib/apache2/modules/libphp*.so /usr/lib*/httpd/modules/libphp*.so \
         /etc/httpd/modules/libphp*.so /usr/local/apache/modules/libphp*.so \
         /opt/cpanel/ea-php*/root/usr/lib*/httpd/modules/libphp*.so; do
  [ -f "$m" ] && rp "$m" >>"$TMP/mods"
done

if [ "$DEEP" = 1 ]; then
  [ "$CSV" = 1 ] || echo "Deep search of / (this can take a while)..." >&2
  find / -xdev -type f \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
       -o -name lsphp -o -name sw-engine \) 2>/dev/null | while IFS= read -r p; do add_cand "$p"; done
  find / -xdev -type f -name 'libphp*.so' 2>/dev/null | while IFS= read -r m; do rp "$m" >>"$TMP/mods"; done
fi

# ---------------------------------------------------------------- probing
while IFS= read -r bin; do
  line=$($TO "$bin" -v 2>/dev/null </dev/null | grep '^PHP [0-9]' | head -n 1)
  if [ -n "$line" ]; then
    ver=$(echo "$line" | sed -n 's/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    sapi=$(echo "$line" | sed -n 's/^PHP [^ ]* (\([^)]*\)).*/\1/p')
  else
    case ${bin##*/} in php*|lsphp*|sw-engine*) ;; *) continue ;; esac
    ver=$(embedded_ver "$bin"); [ -n "$ver" ] || continue
    sapi="(-v failed)"
  fi
  pkg=$(pkg_of "$bin")
  pname=$(echo "$pkg" | awk '{print $1}'); pver=$(echo "$pkg" | awk '{print $2}')
  run=no; grep -Fxq "$bin" "$TMP/running" && run=yes
  up=-
  if [ "$sapi" = cli ]; then
    up=$($TO "$bin" -r 'echo ini_get("session.upload_progress.enabled") ? "on" : "off";' 2>/dev/null </dev/null | tail -n 1)
    [ -n "$up" ] || up="?"
  fi
  emit "$(classify "$ver" "$pname" "$pver")" "${ver:-?}" "${sapi:-?}" "$bin" "$run" "$pkg" "$up"
done <"$TMP/seen"

sort -u "$TMP/mods" | while IFS= read -r m; do
  [ -f "$m" ] || continue
  ver=$(embedded_ver "$m")
  pkg=$(pkg_of "$m")
  pname=$(echo "$pkg" | awk '{print $1}'); pver=$(echo "$pkg" | awk '{print $2}')
  [ -n "$ver" ] || ver=$(echo "$pver" | sed -n 's/^\([0-9]*:\)\{0,1\}\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\2/p')
  run=no; grep -Fq "$m" "$TMP/mods_loaded" && run=yes
  emit "$(classify "$ver" "$pname" "$pver")" "${ver:-?}" "apache2handler" "$m" "$run" "$pkg" "-"
done

# ---------------------------------------------------------------- containers (passive)
if [ -s "$TMP/cproc" ] || [ -s "$TMP/cmods" ] || [ "$CONT" = 1 ]; then load_cnames; fi

# a) PHP processes running inside containers (any runtime). The version is read
#    from /proc/<pid>/exe, i.e. the binary file itself - nothing is executed.
while IFS='|' read -r pid exe; do
  [ -d "/proc/$pid" ] || continue
  cid=$(cid_of "$pid")
  path=${exe% (deleted)}
  case $exe in
    *" (deleted)") echo "container $(cname "$cid"): $path|$pid" >>"$TMP/deleted" ;;
  esac
  container_emit "$cid" "/proc/$pid/exe" "$path" "/proc/$pid/root" yes
done <"$TMP/cproc"

# b) mod_php loaded by Apache inside containers (e.g. php:*-apache images)
while IFS='|' read -r pid mpath; do
  [ -d "/proc/$pid" ] || continue
  cid=$(cid_of "$pid")
  case $mpath in
    *" (deleted)") echo "container $(cname "$cid"): ${mpath% (deleted)}|$pid" >>"$TMP/deleted"; continue ;;
  esac
  container_emit "$cid" "/proc/$pid/root$mpath" "$mpath" "/proc/$pid/root" yes
done <"$TMP/cmods"

CGLOBS='/usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* /usr/bin/lsphp*
  /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm /usr/local/php*/bin/php
  /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php /opt/bitnami/php/bin/php
  /opt/bitnami/php/sbin/php-fpm /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm
  /usr/lib/apache2/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so
  /usr/local/lib/libphp*.so'

env_php_ver() {   # $1 = engine, $2 = container or image id -> PHP version from image metadata
  $TO "$1" inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$2" 2>/dev/null | awk -F= '
    $1=="PHP_VERSION" {print $2; exit}
    $1=="BITNAMI_APP_NAME" && $2 ~ /^php/ {bp=1}
    $1=="APP_VERSION" {av=$2}
    END { if (bp && av != "") print av }' | head -n 1
}

# c) --containers: scan every running container's filesystem for PHP that is
#    installed but not running right now; check stopped containers via metadata.
if [ "$CONT" = 1 ]; then
  for eng in docker podman; do
    command -v "$eng" >/dev/null 2>&1 || continue
    $TO "$eng" ps -a --no-trunc --format '{{.ID}}' 2>/dev/null | while read -r cid; do
      st=$($TO "$eng" inspect -f '{{.State.Running}} {{.State.Pid}}' "$cid" 2>/dev/null)
      running=${st%% *}; cpid=${st##* }
      if [ "$running" = true ] && [ "${cpid:-0}" -gt 0 ] && [ -d "/proc/$cpid/root" ]; then
        root="/proc/$cpid/root"
        for g in $CGLOBS; do
          for f in $root$g; do
            [ -e "$f" ] || [ -L "$f" ] || continue
            inner=$(croot_resolve "$root" "${f#"$root"}")
            [ -f "$root$inner" ] || continue
            container_emit "$cid" "$root$inner" "$inner" "$root" no
          done
        done
      elif [ "$running" != true ]; then
        v=$(env_php_ver "$eng" "$cid")
        [ -n "$v" ] || continue
        grep -Fxq "$cid|stopped" "$TMP/cseen" && continue
        echo "$cid|stopped" >>"$TMP/cseen"
        emit "$(classify "$v" "" "")" "$v" "image-env" "container $(cname "$cid") [stopped]" no "" "-"
      fi
    done
  done
fi

# d) --images: local images, checked through their metadata only (never run or pulled)
if [ "$IMG" = 1 ]; then
  for eng in docker podman; do
    command -v "$eng" >/dev/null 2>&1 || continue
    $TO "$eng" images --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' 2>/dev/null | sort -u -k1,1 \
    | while read -r iid iname; do
      v=$(env_php_ver "$eng" "$iid")
      [ -n "$v" ] || continue
      emit "$(classify "$v" "" "")" "$v" "image-env" "image $iname" no "" "-"
    done
  done
fi

# ---------------------------------------------------------------- step 3: websites
# Map each website to the PHP build that serves it. Read-only: panel config files,
# web-server vhost files, PHP-FPM pool files, and (Plesk) a SELECT on its database.
: >"$TMP/sites"; : >"$TMP/bcache"

add_site() { echo "$1|$2|$3|$4" >>"$TMP/sites"; }   # site|handler|binary|source

bin_info() {   # $1 = binary -> "ver|status|package" (reads the file, does not run it)
  _b=$(rp "$1")
  _c=$(awk -F'|' -v b="$_b" '$1==b {print $2 "|" $3 "|" $4; exit}' "$TMP/bcache")
  if [ -n "$_c" ]; then echo "$_c"; return; fi
  if [ -f "$_b" ]; then
    _v=$(embedded_ver "$_b"); _pk=$(pkg_of "$_b")
    _st=$(classify "$_v" "$(echo "$_pk" | awk '{print $1}')" "$(echo "$_pk" | awk '{print $2}')")
  else _v=""; _pk="handler binary not found"; _st=UNKNOWN; fi
  echo "$_b|${_v:-?}|$_st|$_pk" >>"$TMP/bcache"
  echo "${_v:-?}|$_st|$_pk"
}

first_existing() { for _f in "$@"; do [ -f "$_f" ] && { echo "$_f"; return; }; done; echo "$1"; }

bin_for_branch() {   # $1 = X.Y
  _xy=$(echo "$1" | tr -d .)
  first_existing /usr/sbin/php-fpm"$1" /usr/bin/php"$1" /opt/remi/php"$_xy"/root/usr/sbin/php-fpm \
    /usr/local/php"$_xy"/sbin/php-fpm /usr/local/php"$_xy"/bin/php /www/server/php/"$_xy"/sbin/php-fpm \
    /opt/alt/php-fpm"$_xy"/usr/sbin/php-fpm /opt/alt/php"$_xy"/usr/bin/php
}

xy_dot() { echo "$1" | sed 's/^\([0-9]\)\([0-9]\)$/\1.\2/'; }   # 83 -> 8.3

if [ "$SITES" = 1 ]; then
  # --- cPanel: per-domain PHP from userdata; CloudLinux PHP Selector per user
  if [ -d /var/cpanel/userdata ]; then
    CP_DEF=$(sed -n 's/^default: *//p' /etc/cpanel/ea4/php.conf 2>/dev/null | head -n 1)
    for f in /var/cpanel/userdata/*/*; do
      case ${f##*/} in main|cache|*.cache|*_SSL|*.json|*.yaml|*.db|*.stor) continue ;; esac
      [ -f "$f" ] || continue
      line=$(awk '/^servername:/ {s=$2} /^phpversion:/ {v=$2} END {if (s!="") print s "|" v}' "$f")
      [ -n "$line" ] || continue
      site=${line%%|*}; h=${line#*|}
      case $h in ""|inherit) h=$CP_DEF ;; esac
      src="cPanel"
      cuser=$(echo "$f" | awk -F/ '{print $(NF-1)}')
      if [ "$h" = "$CP_DEF" ] && command -v selectorctl >/dev/null 2>&1; then
        sel=$(awk -F'|' -v u="$cuser" '$1==u {print $2; exit}' "$TMP/selcache" 2>/dev/null)
        if [ -z "$sel" ]; then
          sel=$($TO selectorctl --user-current --user="$cuser" 2>/dev/null | awk '{print $1; exit}')
          echo "$cuser|${sel:-native}" >>"$TMP/selcache"
        fi
        case $sel in [0-9]*.[0-9]*) h="alt-php$(echo "$sel" | tr -d .)"; src="cPanel + PHP Selector" ;; esac
      fi
      case $h in
        ea-php*) b=$(first_existing /opt/cpanel/"$h"/root/usr/sbin/php-fpm /opt/cpanel/"$h"/root/usr/bin/php) ;;
        alt-php*) b=$(first_existing /opt/alt/php"${h#alt-php}"/usr/bin/php /opt/alt/php"${h#alt-php}"/usr/bin/lsphp) ;;
        *) b="" ;;
      esac
      add_site "$site" "${h:-?}" "$b" "$src"
    done
  fi

  # --- Plesk: hosting handler per domain (SELECT only)
  if command -v plesk >/dev/null 2>&1; then
    $TO plesk db -Ne "SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id = d.id" 2>/dev/null \
    | while read -r site h; do
      [ -n "$site" ] || continue
      case $h in
        plesk-php*) n=$(echo "$h" | sed 's/^plesk-php\([0-9]*\).*/\1/'); x=$(xy_dot "$n")
                    b=$(first_existing /opt/plesk/php/"$x"/sbin/php-fpm /opt/plesk/php/"$x"/bin/php) ;;
        *) b=$(rp /usr/bin/php) ;;
      esac
      add_site "$site" "$h" "$b" "Plesk"
    done
  fi

  # --- DirectAdmin: php1/php2... selection per domain, versions from options.conf
  DA_OPT=/usr/local/directadmin/custombuild/options.conf
  if [ -f "$DA_OPT" ]; then
    for f in /usr/local/directadmin/data/users/*/domains/*.conf; do
      [ -f "$f" ] || continue
      site=${f##*/}; site=${site%.conf}
      n=$(sed -n 's/^php1_select=//p' "$f" | head -n 1); n=${n:-1}
      rel=$(sed -n "s/^php${n}_release=//p" "$DA_OPT" | head -n 1)
      xy=$(echo "$rel" | tr -d .)
      b=$(first_existing /usr/local/php"$xy"/sbin/php-fpm"$xy" /usr/local/php"$xy"/sbin/php-fpm /usr/local/php"$xy"/bin/php /usr/local/bin/php)
      add_site "$site" "php${n} (${rel:-?})" "$b" "DirectAdmin"
    done
  fi

  # --- CyberPanel / OpenLiteSpeed: lsphp path in each vhost
  for f in /usr/local/lsws/conf/vhosts/*/vhost.conf; do
    [ -f "$f" ] || continue
    site=$(basename "$(dirname "$f")")
    case $site in Example|_backend) continue ;; esac
    b=$(grep -o '/usr/local/lsws/lsphp[0-9]*/bin/lsphp' "$f" | head -n 1)
    [ -n "$b" ] || continue
    h=$(echo "$b" | sed 's#.*/\(lsphp[0-9]*\)/.*#\1#')
    add_site "$site" "$h" "$b" "OpenLiteSpeed"
  done

  # --- HestiaCP: BACKEND template per web domain
  for f in /usr/local/hestia/data/users/*/web.conf; do
    [ -f "$f" ] || continue
    sed -n "s/.*DOMAIN='\([^']*\)'.*BACKEND='PHP-\([0-9]\)_\([0-9]\)'.*/\1 \2.\3/p" "$f" \
    | while read -r site br; do
      add_site "$site" "PHP-$br" "$(bin_for_branch "$br")" "HestiaCP"
    done
  done

  # --- Generic (no panel data): vhost -> FPM socket -> pool -> PHP build
  if [ ! -s "$TMP/sites" ]; then
    # FPM pools: listen address | pool name | binary
    for f in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf \
             /usr/local/php*/etc/php-fpm.d/*.conf /usr/local/php*/etc/php-fpm.conf /usr/local/etc/php-fpm.d/*.conf \
             /www/server/php/*/etc/php-fpm.conf /opt/alt/php-fpm*/usr/etc/php-fpm.d/*.conf; do
      [ -f "$f" ] || continue
      case $f in
        /etc/php/*) br=$(echo "$f" | cut -d/ -f4); pb=$(first_existing /usr/sbin/php-fpm"$br") ;;
        /etc/opt/remi/*) xy=$(echo "$f" | sed 's#^/etc/opt/remi/php\([0-9]*\)/.*#\1#'); pb=/opt/remi/php"$xy"/root/usr/sbin/php-fpm ;;
        /usr/local/php*) pb=$(first_existing "${f%%/etc/*}"/sbin/php-fpm "${f%%/etc/*}"/bin/php) ;;
        /www/server/php/*) pb="${f%%/etc/*}"/sbin/php-fpm ;;
        /opt/alt/*) pb="${f%%/usr/etc/*}"/usr/sbin/php-fpm ;;
        /usr/local/etc/*) pb=/usr/local/sbin/php-fpm ;;
        *) pb=$(first_existing /usr/sbin/php-fpm) ;;
      esac
      awk -v pb="$pb" '
        /^[ \t]*\[/ { p=$0; gsub(/[][ \t\r]/,"",p); next }
        /^[ \t]*listen[ \t]*=/ { l=$0; sub(/^[^=]*=[ \t]*/,"",l); gsub(/[ \t\r;]+$/,"",l); gsub(/\$pool/,p,l); print l "|" p "|" pb }' "$f"
    done | sed -e 's/^unix://' -e 's/^localhost:/127.0.0.1:/' -e 's/^0\.0\.0\.0:/127.0.0.1:/' \
               -e 's/^\[::1\]:/127.0.0.1:/' -e 's/^\([0-9][0-9]*\)|/127.0.0.1:\1|/' >"$TMP/pools"

    # nginx: server_name + fastcgi_pass (or aaPanel enable-php-XX include)
    for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/conf.d/domains/*.conf \
             /www/server/panel/vhost/nginx/*.conf /usr/local/nginx/conf/vhost/*.conf; do
      [ -f "$f" ] || continue
      awk 'function out() { if (sn!="" && sn!="_" && (fp!="" || ap!="")) print sn "|" fp "|" ap; sn=""; fp=""; ap="" }
        { sub(/#.*/,"") }
        /^[ \t]*server[ \t]*\{/ { out() }
        /(^|[ \t;{])server_name[ \t]/ { if (sn=="" && match($0,/server_name[ \t]+[^ \t;]+/)) { sn=substr($0,RSTART,RLENGTH); sub(/^server_name[ \t]+/,"",sn) } }
        /fastcgi_pass[ \t]/ { if (fp=="" && match($0,/fastcgi_pass[ \t]+[^ \t;]+/)) { fp=substr($0,RSTART,RLENGTH); sub(/^fastcgi_pass[ \t]+/,"",fp) } }
        /enable-php-[0-9]+/ { if (ap=="" && match($0,/enable-php-[0-9]+/)) ap=substr($0,RSTART+11,RLENGTH-11) }
        END { out() }' "$f"
    done >"$TMP/vh"
    # Apache: ServerName + proxy_fcgi handler (or mod_php)
    for f in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /etc/httpd/conf.sites.d/*.conf \
             /etc/httpd/sites-enabled/* /usr/local/apache/conf.d/*.conf; do
      [ -f "$f" ] || continue
      awk 'function out() { if (sn!="") print sn "|" fp "|"; sn=""; fp="" }
        /<VirtualHost/ { out() }
        /^[ \t]*ServerName[ \t]/ { if (sn=="") sn=$2 }
        /proxy:unix:/ { if (fp=="" && match($0,/proxy:unix:[^|" ]+/)) fp=substr($0,RSTART+11,RLENGTH-11) }
        /proxy:fcgi:\/\// { if (fp=="" && match($0,/fcgi:\/\/[^\/" ]+/)) fp=substr($0,RSTART+7,RLENGTH-7) }
        /<\/VirtualHost>/ { out() }
        END { out() }' "$f"
    done >>"$TMP/vh"

    MODPHP=$(head -n 1 "$TMP/mods_loaded")
    while IFS='|' read -r site fp ap; do
      awk -F'|' -v s="$site" '$1==s {f=1} END {exit !f}' "$TMP/sites" && continue
      if [ -n "$ap" ]; then
        add_site "$site" "php-$ap" "$(first_existing /www/server/php/"$ap"/sbin/php-fpm /www/server/php/"$ap"/bin/php)" "nginx"
      elif [ -n "$fp" ]; then
        nfp=$(echo "$fp" | sed -e 's/^unix://' -e 's/^localhost:/127.0.0.1:/')
        pl=$(awk -F'|' -v s="$nfp" '$1==s {print $2 "|" $3; exit}' "$TMP/pools")
        if [ -n "$pl" ]; then
          add_site "$site" "fpm pool ${pl%%|*}" "${pl#*|}" "vhost+pool"
        else
          br=$(echo "$fp" | sed -n 's/.*php-\{0,1\}\([5-9]\)\.\{0,1\}\([0-9]\).*/\1.\2/p')
          if [ -n "$br" ]; then add_site "$site" "$fp" "$(bin_for_branch "$br")" "vhost"
          else add_site "$site" "$fp (no matching FPM pool)" "" "vhost"; fi
        fi
      elif [ -n "$MODPHP" ]; then
        add_site "$site" "mod_php" "${MODPHP% (deleted)}" "apache"
      fi
    done <"$TMP/vh"
  fi

  # Resolve each site's PHP build -> sev|status|version|handler|site|binary|source
  : >"$TMP/srows"
  sort -u -t'|' -k1,1 "$TMP/sites" | while IFS='|' read -r site h b src; do
    if [ -n "$b" ]; then info=$(bin_info "$b"); else info="?|UNKNOWN|"; fi
    v=${info%%|*}; rest=${info#*|}; st=${rest%%|*}
    echo "$(sev "$st")|$st|$v|$h|$site|${b:--}|$src" >>"$TMP/srows"
  done
fi

# Group replaced-but-still-running binaries by path
: >"$TMP/deleted_g"
if [ -s "$TMP/deleted" ]; then
  sort -u "$TMP/deleted" | awk -F'|' '{a[$1]=a[$1] (a[$1]?",":"") $2} END{for(k in a) print k "|" a[k]}' \
    | sort >"$TMP/deleted_g"
fi

# ---------------------------------------------------------------- report
# PHP indicators found in step 1 but nothing could be probed: flag for review
if [ ! -s "$TMP/rows" ] && [ -s "$PRE" ]; then
  echo "4|UNKNOWN|?|?|-|-|PHP present (see step 1) but no runnable binary could be probed||-" >>"$TMP/rows"
fi

n_vuln=$(grep -c '^1|' "$TMP/rows")
n_rev=$(grep -c '^[2-5]|' "$TMP/rows")
n_ok=$(grep -c '^6|' "$TMP/rows")
n_rst=$(grep -c . "$TMP/deleted_g")

if [ "$CSV" = 1 ]; then
  echo "host,os,panel,status,version,sapi,fixed_in,running,binary,package,upload_progress_cli,website"
  sort -t'|' -k1,1n -k7,7 "$TMP/rows" | while IFS='|' read -r k st ver sapi fix run bin pkg up; do
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\n' "$(csvq "$HOST")" "$(csvq "$OS")" "$(csvq "$PANEL")" \
      "$st" "$ver" "$(csvq "$sapi")" "$fix" "$run" "$(csvq "$bin")" "$(csvq "$pkg")" "$up"
  done
  # one row per website: sapi column holds the site's PHP handler
  sort -t'|' -k1,1n -k4,4 -k5,5 "$TMP/srows" | while IFS='|' read -r k st ver h site b src; do
    printf '%s,%s,%s,%s,%s,%s,%s,,%s,%s,,%s\n' "$(csvq "$HOST")" "$(csvq "$OS")" "$(csvq "$PANEL")" \
      "$st" "$ver" "$(csvq "$h")" "$(fixed_for "$ver")" "$(csvq "$b")" "$(csvq "source: $src")" "$(csvq "$site")"
  done
  while IFS='|' read -r path pids; do
    printf '%s,%s,%s,RESTART-NEEDED,,,,yes,%s,%s,,\n' "$(csvq "$HOST")" "$(csvq "$OS")" "$(csvq "$PANEL")" \
      "$(csvq "$path")" "$(csvq "pids: $pids")"
  done <"$TMP/deleted_g"
else
  if [ ! -s "$TMP/rows" ]; then
    echo "${G}No PHP builds found by the deep/container search.${N}"
  else
    printf "${B}%-13s %-9s %-15s %-9s %-4s %s${N}\n" STATUS VERSION SAPI FIXED_IN RUN BINARY
    sort -t'|' -k1,1n -k7,7 "$TMP/rows" | while IFS='|' read -r k st ver sapi fix run bin pkg up; do
      case $st in VULNERABLE) c=$R ;; PATCHED) c=$G ;; *) c=$Y ;; esac
      printf "%s%-13s%s %-9s %-15s %-9s %-4s %s\n" "$c" "$st" "$N" "$ver" "$sapi" "$fix" "$run" "$bin"
      extra=""
      [ -n "$pkg" ] && extra="package: $pkg"
      [ "$up" != "-" ] && extra="${extra:+$extra; }session.upload_progress (CLI ini) = $up"
      [ -n "$extra" ] && printf "%14s-> %s\n" "" "$extra"
    done
  fi
  if [ "$n_rst" -gt 0 ]; then
    echo
    echo "${R}${B}RESTART NEEDED${N} - these processes still run a binary that was replaced on disk:"
    while IFS='|' read -r path pids; do echo "  $path  (pids: $pids)"; done <"$TMP/deleted_g"
  fi
  if [ "$SITES" = 1 ]; then
    echo
    echo "${B}Step 3: websites by PHP version${N}"
    if [ ! -s "$TMP/srows" ]; then
      echo "  No website-to-PHP mapping found (no supported panel data, vhost handler or FPM pool)."
    else
      sort -t'|' -k1,1n -k4,4 -k5,5 "$TMP/srows" | awk -F'|' -v R="$R" -v G="$G" -v Y="$Y" -v N="$N" '
        function flush() { if (key=="") return
          c=(gst=="VULNERABLE")?R:((gst=="PATCHED")?G:Y)
          printf "%s%-13s%s %-9s %s  (%d site%s, %s)\n", c, gst, N, gver, gh, n, (n==1?"":"s"), gsrc
          line="    "; for (i=1;i<=n;i++) { w=s[i] (i<n?", ":"")
            if (length(line)+length(w) > 100) { print line; line="    " } line=line w }
          print line }
        { k=$2 "|" $3 "|" $4
          if (k!=key) { flush(); key=k; gst=$2; gver=$3; gh=$4; gsrc=$7; n=0 }
          s[++n]=$5 }
        END { flush() }'
    fi
  fi
  n_svuln=$(grep -c '^1|' "$TMP/srows"); n_sall=$(grep -c . "$TMP/srows")
  echo
  echo "${B}Summary:${N} ${R}$n_vuln vulnerable${N}, ${Y}$n_rev to review${N}, ${G}$n_ok patched${N}, $n_rst restart-needed"
  [ "$SITES" = 1 ] && echo "         websites: ${R}$n_svuln of $n_sall on a vulnerable PHP build${N}"
  echo
  echo "Status key:"
  echo "  VULNERABLE    upstream build older than the fixed release - upgrade now"
  echo "  CHECK-VENDOR  distro/vendor build that may carry a backported fix; confirm against"
  echo "                the vendor advisory (Ubuntu USN, Debian DSA, RHSA, SUSE, TuxCare)"
  echo "  EOL           PHP 8.1 or older - not covered by upstream fixes; confirm vendor"
  echo "                patch (CloudLinux alt-php, TuxCare ELS) or move sites to 8.2+"
  echo "  NOT-LISTED    branch not named in the advisory - review manually"
  echo "  RUN=yes       binary is currently executing (FPM pool, LSAPI, mod_php, etc.)"
  echo "  CLI ini value may differ from FPM/LSAPI pools; check pool php_admin_value too."
  echo "  container rows: version read from the binary on disk, nothing run inside the container;"
  echo "  image-env rows: version taken from image metadata (PHP_VERSION), image not run."
  echo "  Fix containers by rebuilding/pulling a patched image and recreating the container."
fi

if [ "$n_vuln" -gt 0 ] || [ "$n_rst" -gt 0 ]; then exit 1
elif [ "$n_rev" -gt 0 ]; then exit 2
else exit 0
fi
