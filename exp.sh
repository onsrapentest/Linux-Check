#!/bin/sh

check_version="1"

##( Colors
#
#( fg
red='\e[31m'
lred='\e[91m'
green='\e[32m'
lgreen='\e[92m'
yellow='\e[33m'
lyellow='\e[93m'
blue='\e[34m'
lblue='\e[94m'
magenta='\e[35m'
lmagenta='\e[95m'
cyan='\e[36m'
lcyan='\e[96m'
grey='\e[90m'
lgrey='\e[37m'
white='\e[97m'
black='\e[30m'
##)
#( bg
b_red='\e[41m'
b_lred='\e[101m'
b_green='\e[42m'
b_lgreen='\e[102m'
b_yellow='\e[43m'
b_lyellow='\e[103m'
b_blue='\e[44m'
b_lblue='\e[104m'
b_magenta='\e[45m'
b_lmagenta='\e[105m'
b_cyan='\e[46m'
b_lcyan='\e[106m'
b_grey='\e[100m'
b_lgrey='\e[47m'
b_white='\e[107m'
b_black='\e[40m'
##)
#( special
reset='\e[0;0m'
bold='\e[01m'
italic='\e[03m'
underline='\e[04m'
inverse='\e[07m'
conceil='\e[08m'
crossedout='\e[09m'
bold_off='\e[22m'
italic_off='\e[23m'
underline_off='\e[24m'
inverse_off='\e[27m'
conceil_off='\e[28m'
crossedout_off='\e[29m'
##)


##( Globals
#
# Check user
check_user_id="`id -u`"
check_user="$USER"
[ -z "$check_user" ] && check_user="`id -nu`"
check_pass=""
check_home="$HOME"
[ -z "$check_home" ] && check_home="`grep -E "^$check_user:" /etc/passwd | cut -d: -f6 2>/dev/null`"

# system
check_arch="`uname -m`"
check_linux="`uname -r`"
check_hostname="`hostname`"
check_distro=`command -v lsb_release >/dev/null 2>&1 && lsb_release -d | sed 's/Description:\s*//' 2>/dev/null`
[ -z "$check_distro" ] && check_distro="`(. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null`"
check_distro_codename=`grep -Po '(?<=VERSION_CODENAME=)[^"]+' /etc/os-release 2>/dev/null || echo ""`

##)


check_passed_tests=""
check_executed_tests=""
check_DEBUG=false
check_procmon_data=`mktemp`
check_procmon_lock=`mktemp`
check_cve_tmp=''

# printf
printf "$reset" | grep -q '\\' && alias printf="env printf"

#( internal data
check_common_setuid="
/bin/fusermount
/bin/mount
/bin/ntfs-3g
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/lib64/dbus-1/dbus-daemon-launch-helper
/sbin/mount.ecryptfs_private
/sbin/mount.nfs
/sbin/pam_timestamp_check
/sbin/pccardctl
/sbin/unix2_chkpwd
/sbin/unix_chkpwd
/usr/bin/Xorg
/usr/bin/arping
/usr/bin/at
/usr/bin/beep
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/firejail
/usr/bin/fusermount
/usr/bin/fusermount-glusterfs
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/kismet_capture
/usr/bin/mount
/usr/bin/mtr
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/ntfs-3g
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/pmount
/usr/bin/procmail
/usr/bin/pumount
/usr/bin/staprun
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/traceroute6.iputils
/usr/bin/umount
/usr/bin/weston-launch
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/dbus-1/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/snapd/snap-confine
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/xorg/Xorg.wrap
/usr/libexec/Xorg.wrap
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/cockpit-session
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/gstreamer-1.0/gst-ptp-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/libexec/polkit-agent-helper-1
/usr/libexec/pt_chown
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-client-glib-usb-acl-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/local/share/panasonic/printer/bin/L_H0JDUCZAZ
/usr/sbin/exim4
/usr/sbin/grub2-set-bootflag
/usr/sbin/mount.nfs
/usr/sbin/mtr-packet
/usr/sbin/pam_timestamp_check
/usr/sbin/pppd
/usr/sbin/pppoe-wrapper
/usr/sbin/suexec
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/sbin/uuidd
"
#)
#( regex rules for common setuid
check_common_setuid="$check_common_setuid
/snap/core.*
/var/tmp/mkinitramfs.*
"
#)
#( critical writable files
check_critical_writable="
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/bash.bashrc
/etc/bash_completion
/etc/bash_completion.d/*
/etc/environment
/etc/environment.d/*
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/incron.conf
/etc/incron.d/*
/etc/logrotate.d/*
/etc/modprobe.d/*
/etc/pam.d/*
/etc/passwd
/etc/php*/fpm/pool.d/*
/etc/php/*/fpm/pool.d/*
/etc/profile
/etc/profile.d/*
/etc/rc*.d/*
/etc/rsyslog.d/*
/etc/shadow
/etc/skel/*
/etc/sudoers
/etc/sudoers.d/*
/etc/supervisor/conf.d/*
/etc/supervisor/supervisord.conf
/etc/sysctl.conf
/etc/sysctl.d/*
/etc/uwsgi/apps-enabled/*
/root/.ssh/authorized_keys
"
#critical writable directories
check_critical_writable_dirs="
/etc/bash_completion.d
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/cron.weekly
/etc/environment.d
/etc/logrotate.d
/etc/modprobe.d
/etc/pam.d
/etc/profile.d
/etc/rsyslog.d/
/etc/sudoers.d/
/etc/sysctl.d
/root
"
#)
#( CVE list
check_cve_list="
" #CVElistMARKER
#)
#)

##( Options
check_color=true
check_alt_color=false
check_interactive=true
check_proc_time=60
check_level=0 #Valid levels 0:default, 1:interesting, 2:all
check_selection="" #Selected tests to run. Empty means all.
check_find_opts='-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o' #paths to exclude from searches
check_grep_opts='--color=always'
#)

##( Lib
cecho() { #(
  if $check_color; then
    printf "%b" "$@"
  else
    # If color is disabled we remove it
    printf "%b" "$@" | sed -r 's/(\x1B|\\e)\[[0-9;:]+[A-Za-z]//g'
  fi
} #)
check_recolor() { #(
  o_white="$white"
  o_lyellow="$lyellow"
  o_grey="$grey"
  o_lred="$lred"
  o_lgreen="$lgreen"
  o_lcyan="$lcyan"

  white="$o_grey"
  lyellow="$o_lred"
  grey="$lgrey"
  lred="$red"
  lgreen="$b_lgreen$black"
  lcyan="$cyan"
} #)
check_error() { #(
  cecho "${red}ERROR: ${reset}$*\n" >&2
} #)
check_exclude_paths() { #(
  local IFS="
"
  for p in `printf "%s" "$1" | tr ',' '\n'`; do
    [ "`printf \"%s\" \"$p\" | cut -c1`" = "/" ] || check_error "'$p' is not an absolute path."
    p="${p%%/}"
    check_find_opts="$check_find_opts -path ${p} -prune -o"
  done
} #)
check_set_level() { #(
  case "$1" in
    0|1|2)
      check_level=$(($1))
      ;;
    *)
      check_error "Invalid level."
      exit 1
      ;;
  esac
} #)
check_help() { #(
  echo "Use: $0 [options]"
  echo
  echo " OPTIONS"
  echo "  -c           Disable color"
  echo "  -C           Use alternative color scheme"
  echo "  -i           Non interactive mode"
  echo "  -h           This help"
  echo "  -l LEVEL     Output verbosity level"
  echo "                 0: Show highly important results. (default)"
  echo "                 1: Show interesting results."
  echo "                 2: Show all gathered information."
  echo "  -s SELECTION Comma separated list of sections or tests to run. Available"
  echo "               sections:"
  echo "                 usr: User related tests."
  echo "                 sud: Sudo related tests."
  echo "                 fst: File system related tests."
  echo "                 sys: System related tests."
  echo "                 sec: Security measures related tests."
  echo "                 ret: Recurrent tasks (cron, timers) related tests."
  echo "                 net: Network related tests."
  echo "                 srv: Services related tests."
  echo "                 pro: Processes related tests."
  echo "                 sof: Software related tests."
  echo "                 ctn: Container (docker, lxc) related tests."
  echo "                 cve: CVE related tests."
  echo "               Specific tests can be used with their IDs (i.e.: usr020,sud)"
  echo "  -e PATHS     Comma separated list of paths to exclude. This allows you"
  echo "               to do faster scans at the cost of completeness"
  echo "  -p SECONDS   Time that the process monitor will spend watching for"
  echo "               processes. A value of 0 will disable any watch (default: 60)"
} #)
check_ask() { #(
  local question="$1"
  # We use stderr to print the question
  cecho "${white}${question}: ${reset}" >&2
  read -r answer
  case "$answer" in
    y|Y|yes|Yes|ok|Ok|true|True)
      return 0
      ;;
    *)
      echo "$answer"
      return 1
      ;;
  esac
} #)
check_request_information() { #(
  if $check_interactive; then
  cecho "${grey}---\n"
    [ -z "$check_user" ] && check_user=`check_ask "Could not find current user name. Current user?"`
    check_pass=`check_ask "If you know the current user password, write it here to check sudo privileges"`
  cecho "${grey}---\n"
  fi
} #)
check_test_passed() { #(
  # Checks if a test passed by ID
  local id="$1"
  for i in $check_passed_tests; do
    [ "$i" = "$id" ] && return 0
  done
  return 1
} #)
check_test() { #(
  # Test id
  local id="$1"
  # Minimum level required for this test to show its output
  local level=$(($2))
  # Name of the current test
  local name="$3"
  # Output of the test
  local cmd="$4"
  # Dependencies
  local deps="$5"
  # Variable name where to store the output
  local var="$6"
  # Flags affecting the execution of certain tests
  local flags="$7"

  # Define colors
  local l="${lred}!"
  local r="${lgreen}"
  [ $level -eq 1 ] && l="${lyellow}*" && r="${cyan}"
  [ $level -eq 2 ] && l="${lblue}i" && r="${blue}"

  # Filter selected tests
  if [ "$check_selection" ]; then
    local sel_match=false
    for s in $check_selection; do
      if [ "$s" = "$id" ] || [ "$s" = "`printf \"%s\" \"$id\" | cut -c1-3`" ]; then
        sel_match=true
      fi
    done
    $sel_match || return 0
  fi

  # DEBUG messages
  $check_DEBUG && cecho "${lmagenta}DEBUG: ${lgreen}Executing: ${reset}$cmd\n"

  # Print name and line
  cecho "${white}[${l}${white}] ${grey}${id}${white} $name${grey}"
  for i in $(seq $((${#id}+${#name}+10)) 79); do
    printf "."
  done

  # Check if test should be skipped when running as root
  if [ "$check_user_id" -eq 0 ] && [ "$flags" = "rootskip" ]; then
    cecho " ${grey}skip\n"
    return 1
  fi

  # Check dependencies
  local non_met_deps=""
  for d in $deps; do
    check_test_passed "$d" || non_met_deps="$non_met_deps $d"
  done
  if [ "$non_met_deps" ]; then
    cecho " ${grey}SKIP\n"
    # In "selection mode" we print the missed dependencies
    if [ "$check_selection" ]; then
      cecho "${red}---\n"
      cecho "Dependencies not met:$reset $non_met_deps\n"
      cecho "${red}---$reset\n"
    fi
    return 1
  fi

  # If level is 2 and check_level is less than 2, then we do not execute
  # level 2 tests unless their output needs to be assigned to a variable
  if [ $level -ge 2 ] && [ $check_level -lt 2 ] && [ -z "$var" ]; then
    cecho " ${grey}SKIP\n"
    return 1
  else
    if $check_DEBUG; then
      output="`eval "$cmd" 2>&1`"
    else
      # Execute command if this test's level is in scope
      output="`eval "$cmd" 2>/dev/null`"
    # Assign variable if available
    fi
    [ "$var" ] && [ "$output" ] && readonly "${var}=$output"
    # Mark test as executed
    check_executed_tests="$check_executed_tests $id"
  fi

  if [ -z "$output" ]; then
    cecho " ${grey}NO${reset}\n"
    return 1
  else
    check_passed_tests="$check_passed_tests $id"
    cecho "${red} YES!${reset}\n"
    if [ $check_level -ge $level ]; then
      cecho "${grey}---$reset\n"
      echo "$output"
      cecho "${grey}---$reset\n"
    fi
    return 0
  fi
} #)
check_show_info() { #(
  echo
  cecho "${lcyan} Checker Version:${reset} $check_version\n"
  echo
  cecho "${lblue}        User:${reset} $check_user\n"
  cecho "${lblue}     User ID:${reset} $check_user_id\n"
  cecho "${lblue}    Password:${reset} "
  if [ -z "$check_pass" ]; then
    cecho "${grey}none${reset}\n"
  else
    cecho "******\n"
  fi
  cecho "${lblue}        Home:${reset} $check_home\n"
  cecho "${lblue}        Path:${reset} $PATH\n"
  cecho "${lblue}       umask:${reset} `umask 2>/dev/null`\n"

  echo
  cecho "${lblue}    Hostname:${reset} $check_hostname\n"
  cecho "${lblue}       Linux:${reset} $check_linux\n"
  if [ "$check_distro" ]; then
    cecho "${lblue}Distribution:${reset} $check_distro\n"
  fi
  cecho "${lblue}Architecture:${reset} $check_arch\n"
  echo
  cecho "${green}=====================(${yellow} Current Output Verbosity Level: ${cyan}$check_level ${green})======================${reset}"
  echo
  if [ "$check_user_id" -eq 0 ]; then
    cecho "${green}============(${yellow} Already running as ${red}root${yellow}, will be skipped! ${green})============${reset}"
    echo
  fi
} #)


check_header() { #(
  local id="$1"
  shift
  local title="$*"
  local text="${magenta}"

  # Filter selected tests
  if [ "$check_selection" ]; then
    local sel_match=false
    for s in $check_selection; do
      if [ "`printf \"%s\" \"$s\"|cut -c1-3`" = "$id" ]; then
        sel_match=true
        break
      fi
    done
    $sel_match || return 0
  fi

  for i in $(seq ${#title} 70); do
    text="$text-"
  done
  text="$text(${green} $title ${magenta})-----"
  cecho "$text${reset}\n"
} #)
check_exit() { #(
  local ec=1
  local text="\n${magenta}=================================="
  [ "$1" ] && ec=$1
  text="$text(${green} FINISHED ${magenta})=================================="
  cecho "$text${reset}\n"
  rm -f "$check_procmon_data"
  rm -f "$check_procmon_lock"
  rm -f "$check_cve_tmp"
  exit "$ec"
} #)
check_procmon() { #(
  # monitor processes
  #NOTE: The first number will be the number of occurrences of a process due to
  #      uniq -c
  local ps_args
  local ps_busybox
  if ps -V 2>&1 | grep -iq busybox; then
    ps_args='-o pid,user,args'
    ps_busybox=true
  else
    ps_args="-ewwwo start_time,pid,user:50,args"
    ps_busybox=false
  fi
  while [ -f "$check_procmon_lock" ]; do
    if $ps_busybox; then
      ps $ps_args | sed 's/^\([0-9]*\)/? \1 /g'
    else
      ps $ps_args
    fi
    sleep 0.001
  done | grep -Ev "(pid,user|$check_user *sed s/)" | sed 's/^ *//g' | tr -s '[:space:]' | grep -Ev "PID *USER *COMMAND" | grep -Ev '[^ ]+ [^ ]+ [^ ]+ \[' | sort -Mr | uniq -c | sed 's/^ *//g' > "$check_procmon_data"
} #)
check_proc_print() { #(
  # Pretty prints output from check_procmom received via stdin
  if $check_color; then
    printf "${green}%s %8s %8s %s\n" "START" "PID" "USER" "COMMAND"
  else
    printf "%s %8s %8s %s\n" "START" "PID" "USER" "COMMAND"
  fi
  while read -r l; do
    p_num=`echo "$l" | cut -d" " -f1`
    p_time=`echo "$l" | cut -d" " -f2`
    p_pid=`echo "$l" | cut -d" " -f3`
    p_user=`echo "$l" | cut -d" " -f4`
    p_args=`echo "$l" | cut -d" " -f5-`

    if $check_color; then
      if [ $((p_num)) -lt 20 ]; then # few times probably periodic
        printf "${red}%s ${reset}%8s ${yellow}%8s ${red}%s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
      else
        printf "${magenta}%s ${reset}%8s ${yellow}%8s ${reset}%s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
      fi
    else
      printf "%s %8s %8s %s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
    fi
  done
} #)
check_get_distro_codename() { #(
  # Get the distribution name
  #
  # ubuntu, debian, centos, redhat, opsuse, fedora, rocky
  local distro="${grey}unknown${reset}"
  if type lsb_release >/dev/null 2>&1; then
    distro=`lsb_release -is`
  elif [ -f /etc/os-release ]; then
    distro=`grep -E '^ID=' /etc/os-release | cut -f2 -d=`
    echo "$distro" | grep -qi opensuse && distro=opsuse
    echo "$distro" | grep -qi rhel && distro=redhat
  elif [ -f /etc/redhat-release ]; then
    grep -qi "centos"  /etc/redhat-release && distro=centos
    grep -qi "fedora"  /etc/redhat-release && distro=fedora
    grep -qi "red hat" /etc/redhat-release && distro=redhat
    grep -qi "rocky"   /etc/redhat-release && distro=rocky
  fi
  printf '%s' "$distro" | tr '[:upper:]' '[:lower:]' | tr -d \"\'
} #)
check_is_version_bigger() { #(
  # check if version v1 is bigger than v2
  local v1="$1"; local v2="$2" ; local vc
  [ "$v1" = "$v2" ] && return 1 # equal is not bigger
  vc="`printf "%s\n%s\n" "$v1" "$v2" | sort -rV | head -n1`"
  [ "$v1" = "$vc" ] && return 0
  return 1
} #)
check_get_pkg_version() { #(
  # get package version depending on distro
  # returns 2 if distro is unknown
  # returns 1 if package is not installed (or doesn't exist)
  # returns 0 on success, and prints out the package version
  pkg_name="$1"
  case "$check_distro_codename" in
    debian|ubuntu)
      pkg_version=`dpkg -l "$pkg_name" 2>/dev/null | grep -E '^[ih]i' | tr -s ' ' | cut -d' ' -f3`
      ;;
    centos|redhat|fedora|opsuse|rocky|amzn)
      pkg_version=`rpm -q "$pkg_name" 2>/dev/null`
      pkg_version="${pkg_version##"$pkg_name"-}"
      pkg_version=`echo "$pkg_version" | sed -E 's/\.(aarch64|armv7hl|i686|noarch|ppc64le|s390x|x86_64)$//'`
      ;;
    *)
      return 2
      ;;
  esac
  [ -z "$pkg_version" ] && return 1
  printf "%s" "$pkg_version"
  return 0
} #)
#)
#)

########################################################################( TESTS
#
#  A successful test will receive some output while a failed tests will receive
# an empty string.
#
########################################################################( users
check_run_tests_users() {
  check_header "usr" "users"

  #user groups
  check_test "usr000" "2" \
    "Current user groups" \
    'groups' \
    "" \
    "check_user_groups"

  #user in an administrative group
  check_test "usr010" "1" \
    "Is current user in an administrative group?" \
    'grep $check_grep_opts -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep $check_grep_opts -E "(:|,)$check_user"'

  #other users in an administrative group
  check_test "usr020" "1" \
    "Are there other users in administrative groups?" \
    'grep $check_grep_opts -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep -Ev ":$|:$check_user$" | grep $check_grep_opts -Ei ":[,a-z_-]+\$"'

  #other users with shell
  check_test "usr030" "1" \
    "Other users with shell" \
    'grep $check_grep_opts -E ":/[a-z/]+sh\$" /etc/passwd' \
    "" \
    "check_shell_users"

  #user env information
  check_test "usr040" "2" \
    "Environment information" \
    'env | grep -v "LS_COLORS"'

  #dump user groups
  check_test "usr050" "2" \
    "Groups for other users" \
    'cat /etc/group'

  #dump users
  check_test "usr060" "2" \
    "Other users" \
    'cat /etc/passwd'

  #find defined PATHs
  check_test "usr070" "1" \
    "PATH variables defined inside /etc" \
    'for p in `grep -ERh "^ *PATH=.*" /etc/ 2> /dev/null | tr -d \"\'"'"' | cut -d= -f2 | tr ":" "\n" | sort -u`; do [ -d "$p" ] && echo "$p";done' \
    "" \
    "check_exec_paths"

  #check if . is in PATHs
  check_test "usr080" "0" \
    "Is '.' in a PATH variable defined inside /etc?" \
    'for ep in $check_exec_paths; do [ "$ep" = "." ] && grep -ER "^ *PATH=.*" /etc/ 2> /dev/null | tr -d \"\'"'"' | grep -E "[=:]\.([:[:space:]]|\$)";done' \
    "usr070"
}
#)

#########################################################################( sudo
check_run_tests_sudo() {
  check_header "sud" "sudo"

  check_sudo=false
  check_sudo_commands=""

  # Kiểm tra sudo không cần mật khẩu
  check_test "sud000" "0" \
    "Can we sudo without a password?" \
    'echo "" | sudo -nS id' && check_sudo=true

  if ! $check_sudo; then
    check_test "sud010" "0" \
      "Can we list sudo commands without a password?" \
      'echo "" | sudo -nS -l' \
      "" \
      "check_sudo_commands"
  fi

  if [ "$check_pass" ]; then

    check_test "sud020" "0" \
      "Can we sudo with a password?" \
      'echo "$check_pass" | sudo -S id' && check_sudo=true

    if ! $check_sudo && [ -z "$check_sudo_commands" ]; then

      check_test "sud030" "0" \
        "Can we list sudo commands with a password?" \
        'echo "$check_pass" | sudo -S -l' \
        "" \
        "check_sudo_commands"
    fi
  fi


  check_test "sud040" "1" \
    "Can we read sudoers files?" \
    'grep -R "" /etc/sudoers*'


  check_test "sud050" "1" \
    "Do we know if any other users used sudo?" \
    'for uh in $(cut -d: -f1,6 /etc/passwd); do [ -f "${uh##*:}/.sudo_as_admin_successful" ] && echo "${uh%%:*}"; done'
}

#)

##################################################################( file system
check_run_tests_filesystem() {
  check_header "fst" "file system"

  # Writable files outside user's home
  check_test "fst000" "1" \
    "Writable files outside user's home" \
    'find / -path "$check_home" -prune -o $check_find_opts -not -type l -writable -print;
    # Add symlinks owned by the user
    find / -path "$check_home" -prune -o $check_find_opts -type l -user $check_user -print' \
    "" \
    "check_user_writable" \
    "rootskip"

  # Setuid binaries
  check_test "fst010" "1" \
    "Binaries with setuid bit" \
    'find / $check_find_opts -perm -4000 -type f -print' \
    "" \
    "check_setuid_binaries"

  # Uncommon setuid binaries
  check_test "fst020" "0" \
    "Uncommon setuid binaries" \
    'local setuidbin="$check_setuid_binaries"; local IFS="
"; for cs in ${check_common_setuid}; do setuidbin=`printf "$setuidbin\n" | grep -Ev "^$cs$"`; done; printf "$setuidbin\n"' \
    "fst010"

  # Write permissions on setuid binaries
  check_test "fst030" "0" \
    "Can we write to any setuid binary?" \
    'for b in $check_setuid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b"; done' \
    "fst010"

  # Setgid binaries
  check_test "fst040" "1" \
    "Binaries with setgid bit" \
    'find / $check_find_opts -perm -2000 -type f -print' \
    "check_setgid_binaries"

  # Uncommon setgid binaries
  check_test "fst050" "0" \
    "Uncommon setgid binaries" \
    'printf "$check_setgid_binaries\n" | grep -Ev "^/(bin|sbin|usr/bin|usr/lib|usr/sbin)"' \
    "fst040"

  # Write permissions on setgid binaries
  check_test "fst060" "0" \
    "Can we write to any setgid binary?" \
    'for b in $check_setgid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b"; done' \
    "fst040"

  # Can we read /root
  check_test "fst070" "1" \
    "Can we read /root?" \
    'ls -ahl /root/'

  # Check /home permissions
  check_test "fst080" "1" \
    "Can we read subdirectories under /home?" \
    'for h in /home/*; do [ -d "$h" ] && [ "$h" != "$check_home" ] && ls -la "$h/"; done'

  # Check for SSH files in home directories
  check_test "fst090" "1" \
    "SSH files in home directories" \
    'for h in $(cut -d: -f6 /etc/passwd | sort -u | grep -Ev "^(/|/dev|/bin|/proc|/run/.*|/var/run/.*)$"); do find "$h" \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "*id_ecdsa*" -o -name "*id_ed25519*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; ; done'

  # Useful binaries
  check_test "fst100" "1" \
    "Useful binaries" \
    'which curl; which dig; which gcc; which nc.openbsd; which nc; which netcat; which nmap; which socat; which wget'

  # Other interesting files in home directories
  check_test "fst110" "1" \
    "Other interesting files in home directories" \
    'for h in $(cut -d: -f6 /etc/passwd); do find "$h" \( -name "*.rhosts" -o -name ".git-credentials" -o -name ".*history" \) -maxdepth 1 -exec ls -la {} \; ;'

  # Credentials in /etc/fstab and /etc/mtab
  check_test "fst120" "0" \
    "Are there any credentials in fstab/mtab?" \
    'grep $check_grep_opts -Ei "(user|username|login|pass|password|pw|credentials|cred)[=:]" /etc/fstab /etc/mtab'

  # Check if current user has mail
  check_test "fst130" "1" \
    "Does '$check_user' have mail?" \
    'ls -l "/var/mail/$check_user"'

  # Access other users' mail
  check_test "fst140" "0" \
    "Can we access other users mail?" \
    'for f in /var/mail/*; do [ "$f" != "/var/mail/$check_user" ] && [ -r "$f" ] && echo "$f"; done'

  # Check for code repositories
  check_test "fst150" "1" \
    "Looking for GIT/SVN repositories" \
    'find / $check_find_opts \( -name ".git" -o -name ".svn" \) -print'

  # Write permissions to critical files
  check_test "fst160" "0" \
    "Can we write to files that can give us root" \
    'for uw in $check_user_writable; do [ -f "$uw" ] && IFS="
"; for cw in ${check_critical_writable}; do [ "$cw" = "$uw" ] && [ -w "$cw" ] && ls -l $cw; done; done' \
    "fst000"

  # Write permissions to critical directories
  check_test "fst170" "0" \
    "Can we write to critical directories" \
    'for uw in $check_user_writable; do [ -d "$uw" ] && IFS="
"; for cw in ${check_critical_writable_dirs}; do [ "$cw" = "$uw" ] && [ -w "$cw" ] && ls -ld $cw; done; done' \
    "fst000"

  # Write permissions to directories inside PATHS
  check_test "fst180" "0" \
    "Can we write to directories from PATH defined in /etc?" \
    'for ep in $check_exec_paths; do [ -d "$ep" ] && [ -w "$ep" ] && ls -ld "$ep"; done' \
    "usr070"

  # Read backups
  check_test "fst190" "0" \
    "Can we read any backup?" \
    'find / $check_find_opts -path /usr/lib -prune -o -path /usr/share -prune -o -regextype egrep -iregex ".*(backup|dump|cop(y|ies)|bak|bkp)[^/]*\.(sql|tgz|tar|zip)?\.?(gz|xz|bzip2|bz2|lz|7z)?" -readable -type f -exec ls -al {} \;'

  # Credentials in shell history files
  check_test "fst200" "0" \
    "Are there possible credentials in any shell history file?" \
    'for h in .bash_history .history .histfile .zhistory; do [ -f "$check_home/$h" ] && grep $check_grep_opts -Ei "(user|username|login|pass|password|pw|credentials)[=: ][a-z0-9]+" "$check_home/$h" | grep -v "systemctl"; done'

  # NFS exports with no_root_squash
  check_test "fst210" "0" \
    "Are there NFS exports with 'no_root_squash' option?" \
    'grep $check_grep_opts "no_root_squash" /etc/exports'

  # NFS exports with no_all_squash
  check_test "fst220" "1" \
    "Are there NFS exports with 'no_all_squash' option?" \
    'grep $check_grep_opts "no_all_squash" /etc/exports'

  # Files owned by user
  check_test "fst500" "2" \
    "Files owned by user '$check_user'" \
    'find / $check_find_opts -user $check_user -type f -exec ls -al {} \;' \
    "" "" "rootskip"

  # Check for SSH files anywhere
  check_test "fst510" "2" \
    "SSH files anywhere" \
    'find / $check_find_opts \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "*id_ecdsa*" -o -name "*id_ed25519*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \;' 

  # Dump hosts.equiv file
  check_test "fst520" "2" \
    "Dump hosts.equiv file" \
    'cat /etc/hosts.equiv' \
    "" "" "rootskip"
}

#####################################################################( network


check_run_tests_network() {
  check_header "net" "network"

  # Check for open ports
  check_test "net000" "1" \
    "Open ports on the system" \
    'netstat -tuln | grep -E "tcp|udp"' \
    "" \
    "check_open_ports"

  # Check for processes listening on open ports
  check_test "net010" "1" \
    "Processes listening on open ports" \
    'ss -tuln | awk '\''/LISTEN/ {print $1, $4, $6}'\'' | sort -u'

  # Check for services running as root
  check_test "net020" "1" \
    "Services running as root" \
    'ps aux | grep -E "root.*(sshd|nginx|apache|httpd|mysql|postgres|ftp)"'

  # Check for vulnerable services
  check_test "net030" "0" \
    "Potentially vulnerable services" \
    'nmap -sV -p- 127.0.0.1' \
    "" \
    "rootskip"

  # Check for writable network configurations
  check_test "net040" "0" \
    "Writable network configuration files" \
    'find /etc/network /etc/sysconfig/network-scripts -type f -writable -exec ls -la {} \;' 

  # Check ARP table for suspicious entries
  check_test "net050" "1" \
    "Suspicious ARP table entries" \
    'arp -a'

  # Check routing table
  check_test "net060" "1" \
    "Routing table" \
    'ip route show'

  # Check DNS resolver configuration
  check_test "net070" "1" \
    "DNS resolver configuration" \
    'cat /etc/resolv.conf'

  # Check for IP forwarding enabled
  check_test "net080" "0" \
    "Is IP forwarding enabled?" \
    'sysctl net.ipv4.ip_forward | grep -q "1" && echo "Enabled" || echo "Disabled"'

  # Check for listening services on unusual ports
  check_test "net090" "0" \
    "Services listening on unusual ports" \
    'ss -tuln | awk '\''/LISTEN/ && $4 !~ /:22|:80|:443/ {print $4}'\'''

  # Check for world-readable network configuration files
  check_test "net100" "0" \
    "World-readable network configuration files" \
    'find /etc/network /etc/sysconfig/network-scripts -type f -perm -004 -exec ls -la {} \;'

  # Check for interfaces in promiscuous mode
  check_test "net110" "0" \
    "Interfaces in promiscuous mode" \
    'ip link show | grep -i "PROMISC"'

  # Check for active VPN connections
  check_test "net120" "1" \
    "Active VPN connections" \
    'ifconfig | grep -i "tun\|tap"'

  # Check for suspicious connections
  check_test "net130" "1" \
    "Suspicious outgoing connections" \
    'netstat -antp | grep -v "127.0.0.1"'

  # Check for default gateway reachability
  check_test "net140" "1" \
    "Default gateway reachability" \
    'ping -c 4 $(ip route show | grep "default" | awk '\''{print $3}'\'')'

  # Check for active SSH sessions
  check_test "net150" "1" \
    "Active SSH sessions" \
    'who | grep -i ssh'

  # Check for duplicated IPs in the local network
  check_test "net160" "1" \
    "Duplicated IPs in the network" \
    'arp-scan -l | awk '\''{print $1}'\'' | sort | uniq -d'

  # Check for known misconfigurations in /etc/hosts
  check_test "net170" "0" \
    "Misconfigurations in /etc/hosts" \
    'grep -E "localhost.*127.0.1.1|.*loopback.*" /etc/hosts'

  # Look for plaintext credentials in configuration files
  check_test "net180" "0" \
    "Plaintext credentials in network configurations" \
    'grep -iE "(password|secret|key)" /etc/network/* /etc/sysconfig/network-scripts/*'

  # Check for services using weak ciphers
  check_test "net190" "0" \
    "Services using weak ciphers" \
    'sslyze --regular localhost'
}
#####################################################################( tasks

check_run_tests_recurrent_tasks() {
  check_header "tasks" "recurrent_tasks"

  # Check for cron jobs for all users
  check_test "tasks000" "1" \
    "Cron jobs for all users" \
    'for user in $(cut -f1 -d: /etc/passwd); do echo "Cron jobs for $user:"; crontab -u $user -l 2>/dev/null || echo "No jobs found"; done'

  # Check for system-wide cron jobs
  check_test "tasks010" "1" \
    "System-wide cron jobs" \
    'ls -la /etc/cron.* /etc/crontab'

  # Check for suspicious entries in cron jobs
  check_test "tasks020" "0" \
    "Suspicious entries in cron jobs" \
    'grep -E "(curl|wget|nc|bash|sh|python|perl)" /etc/cron.*/* /var/spool/cron/* /etc/crontab 2>/dev/null'

  # Check for at jobs
  check_test "tasks030" "1" \
    "AT jobs for all users" \
    'for user in $(cut -f1 -d: /etc/passwd); do echo "AT jobs for $user:"; atq -u $user 2>/dev/null || echo "No AT jobs found"; done'

  # Check for periodic tasks (systemd timers)
  check_test "tasks040" "1" \
    "Active systemd timers" \
    'systemctl list-timers --all'

  # Check for misconfigured cron permissions
  check_test "tasks050" "0" \
    "Misconfigured cron permissions" \
    'ls -la /etc/cron.allow /etc/cron.deny'

  # Check for orphaned cron files
  check_test "tasks060" "0" \
    "Orphaned cron files" \
    'find /etc/cron.* -type f -exec grep -L "run-parts" {} \;'

  # Check for cron jobs running as root
  check_test "tasks070" "1" \
    "Cron jobs running as root" \
    'crontab -u root -l 2>/dev/null || echo "No root cron jobs found"'

  # Check for repeated failure logs in cron
  check_test "tasks080" "1" \
    "Failed cron jobs" \
    'grep CRON /var/log/syslog 2>/dev/null | grep -i "error" || echo "No failed jobs found"'

  # Check for suspicious user in cron.allow or cron.deny
  check_test "tasks090" "0" \
    "Suspicious users in cron.allow or cron.deny" \
    'cat /etc/cron.allow /etc/cron.deny 2>/dev/null'

  # Check for backup-related cron jobs
  check_test "tasks100" "1" \
    "Backup-related cron jobs" \
    'grep -i "backup" /etc/cron.*/* /var/spool/cron/* /etc/crontab 2>/dev/null'

  # Check for disabled systemd timers
  check_test "tasks110" "1" \
    "Disabled systemd timers" \
    'systemctl list-timers --all | grep -i "inactive"'

  # Check for temporary scripts executed by cron
  check_test "tasks120" "0" \
    "Temporary scripts executed by cron" \
    'grep -E "/tmp|/var/tmp" /etc/cron.*/* /var/spool/cron/* /etc/crontab'

  # Check for overly permissive cron files
  check_test "tasks130" "0" \
    "Overly permissive cron files" \
    'find /etc/cron.* -type f -perm -o+w -exec ls -la {} \;'

  # Check for repetitive failed jobs
  check_test "tasks140" "1" \
    "Repetitive failed jobs" \
    'grep "cron" /var/log/syslog | grep "fail" | sort | uniq -c | sort -rn'

  # Check for unexpected binary execution in cron
  check_test "tasks150" "0" \
    "Unexpected binary execution in cron jobs" \
    'grep -E "/usr/bin/|/usr/local/bin/" /etc/cron.*/* /var/spool/cron/* /etc/crontab'

  # Look for user-defined systemd timers
  check_test "tasks160" "1" \
    "User-defined systemd timers" \
    'find /etc/systemd/system -name "*.timer"'

  # Check for tasks scheduled to run too frequently
  check_test "tasks170" "0" \
    "Tasks running too frequently" \
    'grep -E "\* \* \* \* \*" /etc/cron.*/* /var/spool/cron/* /etc/crontab'

  # Check for cron jobs with unexpected environment variables
  check_test "tasks180" "0" \
    "Unexpected environment variables in cron jobs" \
    'grep -E "PATH|LD_LIBRARY_PATH|PYTHONPATH" /etc/cron.*/* /var/spool/cron/* /etc/crontab'
}


#####################################################################( software
check_run_tests_software() {
  check_header "sof" "software"

  #checks to see if root/root will get us a connection
  check_test "sof000" "0" \
    "Can we connect to MySQL with root/root credentials?" \
    'mysqladmin -uroot -proot version'

  #checks to see if we can connect as root without password
  check_test "sof010" "0" \
    "Can we connect to MySQL as root without password?" \
    'mysqladmin -uroot version'

  #check if there are credentials stored in .mysql-history
  check_test "sof015" "0" \
    "Are there credentials in mysql_history file?" \
    'grep -Ei "(pass|identified by|md5\()" "$check_home/.mysql_history"'

  #checks to see if we can connect to postgres templates without password
  check_test "sof020" "0" \
    "Can we connect to PostgreSQL template0 as postgres and no pass?" \
    'psql -U postgres template0 -c "select version()" | grep version'
  check_test "sof020" "0" \
    "Can we connect to PostgreSQL template1 as postgres and no pass?" \
    'psql -U postgres template1 -c "select version()" | grep version'
  check_test "sof020" "0" \
    "Can we connect to PostgreSQL template0 as psql and no pass?" \
    'psql -U pgsql template0 -c "select version()" | grep version'
  check_test "sof020" "0" \
    "Can we connect to PostgreSQL template1 as psql and no pass?" \
    'psql -U pgsql template1 -c "select version()" | grep version'

  #installed apache modules
  check_test "sof030" "1" \
    "Installed apache modules" \
    'apache2ctl -M; httpd -M'

  #find htpassword files
  check_test "sof040" "0" \
    "Found any .htpasswd files?" \
    'find / $check_find_opts -name "*.htpasswd" -print -exec cat {} \;'

  #check if there are ssh private keys in ssh-agent
  check_test "sof050" "0" \
    "Are there private keys in ssh-agent?" \
    'ssh-add -l | grep -iv "agent has no identities"'

  #check if there are gpg keys in gpg-agent
  check_test "sof060" "0" \
    "Are there gpg keys cached in gpg-agent?" \
    'gpg-connect-agent "keyinfo --list" /bye | grep "D - - 1"'

  #check if there is a writable ssh-agent socket
  check_test "sof070" "0" \
    "Can we write to a ssh-agent socket?" \
    'for f in $check_user_writable; do test -S "$f" && printf "$f" | grep -Ea "ssh-[A-Za-z0-9]+/agent\.[0-9]+"; done' \
    "fst000"

  #check if there is a writable gpg-agent socket
  check_test "sof080" "0" \
    "Can we write to a gpg-agent socket?" \
    'for f in $check_user_writable; do test -S "$f" && printf "$f" | grep -a "gpg-agent"; done' \
    "fst000"

  #find keepass database files
  check_test "sof090" "0" \
    "Found any keepass database files?" \
    'find / $check_find_opts -regextype egrep -iregex ".*\.kdbx?" -readable -type f -print'

  #find pass database files
  check_test "sof100" "0" \
    "Found any 'pass' store directories?" \
    'find / $check_find_opts -name ".password-store" -readable -type d -print'

  #check if any tmux session is active
  check_test "sof110" "0" \
    "Are there any tmux sessions available?" \
    'tmux list-sessions'

  #check for all tmux sessions for other users
  check_test "sof120" "1" \
    "Are there any tmux sessions from other users?" \
    'find /tmp -type d -regex "/tmp/tmux-[0-9]+" ! -user $check_user'

  #check if we have write access to other users tmux sessions
  check_test "sof130" "0" \
    "Can we write to tmux session sockets from other users?" \
    'find /tmp -writable -type s -regex "/tmp/tmux-[0-9]+/.+" ! -user $check_user -exec ls -l {} +'

  #check if there is any active screen session
  check_test "sof140" "0" \
    "Are any screen sessions available?" \
    'screen -ls >/dev/null && screen -ls'

  #find other users screen sessions
  check_test "sof150" "1" \
    "Are there any screen sessions from other users?" \
    'find /run/screen -type d -regex "/run/screen/S-.+" ! -user $check_user'

  #find writable screen session sockets from other users
  check_test "sof160" "0" \
    "Can we write to screen session sockets from other users?" \
    'find /run/screen -type s -writable -regex "/run/screen/S-.+/.+" ! -user $check_user -exec ls -l {} +'

  #check connection to mongoDB
  check_test "sof170" "1" \
    "Can we access MongoDB databases without credentials?" \
    'echo "show dbs" | mongo --quiet | grep -E "(admin|config|local)"'

  #find kerberos credentials
  check_test "sof180" "0" \
    "Can we access any Kerberos credentials?" \
    'find / $check_find_opts -name "*.so" -prune -o \( -name "krb5cc*" -o -name "*.ccache" -o -name "*.kirbi" -o -name "*.keytab" \) -type f -readable -exec ls -lh {} +'

  #sudo version - check to see if there are any known vulnerabilities with this
  check_test "sof500" "2" \
    "Sudo version" \
    'sudo -V | grep "Sudo version"'

  #mysql details - if installed
  check_test "sof510" "2" \
    "MySQL version" \
    'mysql --version'

  #postgres details - if installed
  check_test "sof520" "2" \
    "Postgres version" \
    'psql -V'

  #apache details - if installed
  check_test "sof530" "2" \
    "Apache version" \
    'apache2 -v; httpd -v'

  #check tmux version
  check_test "sof540" "2" \
    "Tmux version" \
    'tmux -V'

  #check screen version
  check_test "sof550" "2" \
    "Screen version" \
    'screen -v'

}
#)

###################################################################( containers
check_run_tests_containers() {
  check_header "ctn" "containers"

  #check to see if we are in a docker container
  check_test "ctn000" "1" \
    "Are we in a docker container?" \
    'grep -i docker /proc/self/cgroup; find / $check_find_opts -name "*dockerenv*" -exec ls -la {} \;'

  #check to see if current host is running docker services
  check_test "ctn010" "1" \
    "Is docker available?" \
    'docker --version; docker ps -a; docker images'

  #is user a member of the docker group
  check_test "ctn020" "0" \
    "Is the user a member of the 'docker' group?" \
    'groups | grep -o docker'

  #check to see if we are in an lxc container
  check_test "ctn200" "1" \
    "Are we in a lxc container?" \
    'grep -a container=lxc /proc/1/environ | tr -d "\0"'

  #is user a member of any lxd/lxc group
  check_test "ctn210" "0" \
    "Is the user a member of any lxc/lxd group?" \
    'groups | grep $check_grep_opts "lxc\|lxd"'
}
#)

####################################################################( processes
check_run_tests_processes() {
  check_header "pro" "processes"

  #wait for the process monitor to finish gathering data
  check_test "pro000" "2" \
    "Waiting for the process monitor to finish" \
    'while [ ! -s "$check_procmon_data" ]; do sleep 1; done; cat "$check_procmon_data"'\
    "" \
    "check_procs"

  #look for the paths of the process binaries
  check_test "pro001" "2" \
    "Retrieving process binaries" \
    'printf "%s" "$check_procs" | cut -d" " -f5 | sort -u | xargs -r which' \
    "pro000" \
    'check_proc_bin'

  #look for the users running the
  check_test "pro002" "2" \
    "Retrieving process users" \
    'printf "%s" "$check_procs" | cut -d" " -f4 | sort -u' \
    "pro000" \
    'check_proc_users'

  #check if we have write permissions in any process binary
  check_test "pro010" "0" \
    "Can we write in any process binary?" \
    'for b in $check_proc_bin; do [ -w "$b" ] && echo $b; done'\
    "pro001"

  #list processes running as root
  check_test "pro020" "1" \
    "Processes running with root permissions" \
    'printf "%s" "$check_procs" | grep -E "^[^ ]+ [^ ]+ [^ ]+ root" | check_proc_print' \
    "pro000"

  #list processes running as users with shell
  check_test "pro030" "1" \
    "Processes running by non-root users with shell" \
    'for user in `printf "%s\n" "$check_shell_users" | cut -d: -f1 | grep -v root`; do printf "%s" "$check_proc_users" | grep -qE "(^| )$user( |\$)" && printf "\n\n------ $user ------\n\n\n" && printf "%s" "$check_procs" | grep -E "^[^ ]+ [^ ]+ [^ ]+ $user" | check_proc_print; done' \
    "usr030 pro000 pro002"

  #running processes
  check_test "pro500" "2" \
    "Running processes" \
    'printf "%s\n" "$check_procs" | check_proc_print' \
    "pro000"

  #list running process binaries and their permissions
  check_test "pro510" "2" \
    "Running process binaries and permissions" \
    'printf "%s\n" "$check_proc_bin" | xargs ls -l' \
    "pro001"
}
#)

#########################################################################( CVEs
check_run_tests_cves() {
  check_header "cve" "CVEs"

  if [ "${#check_cve_list}" = 1 ]; then
    if [ -z "$check_selection" ] || printf "%s" "$check_selection" | grep -iq 'cve'; then
      printf "%s\n%s\n%s\n%s\n" \
        "  [INFO] CVE tests are currently being updated." \
        "  To enable CVE testing, please download the latest version" \
        "  from the GitHub releases page." 
    fi
  else
    # Xử lý từng CVE trong danh sách
    for check_cve in $check_cve_list; do
      # Giải mã và xử lý nội dung CVE
      eval "$(printf '%s' "$check_cve" | base64 -d | gunzip -c)"

      # Thực hiện kiểm tra cho từng CVE
      check_test "$check_cve_id" "$check_cve_level" \
        "$check_cve_description" \
        "check_cve_test"
    done
  fi
}

#)
#
##)

#( Main
main() {
  while getopts "hcCil:e:p:s:S" option; do
    case "${option}" in
      c) check_color=false; check_grep_opts='--color=never';;
      C) check_alt_color=true;;
      e) check_exclude_paths "${OPTARG}";;
      i) check_interactive=false;;
      l) check_set_level "${OPTARG}";;
      s) check_selection="`printf \"%s\" \"${OPTARG}\"|sed 's/,/ /g'`";;
      p) check_proc_time="${OPTARG}";;
      S) check_serve; exit $?;;
      h) check_help; exit 0;;
      *) check_help; exit 1;;
    esac
  done

  #trap to exec on SIGINT
  trap "check_exit 1" 2

  # use alternative color scheme
  $check_alt_color && check_recolor

  check_request_information
  check_show_info
  PATH="$PATH:/sbin:/usr/sbin" #fix path just in case
  check_distro_codename=`check_get_distro_codename`

  check_procmon &
  (sleep "$check_proc_time"; rm -f "$check_procmon_lock") &


  check_run_tests_users
  check_run_tests_sudo
  check_run_tests_filesystem
  check_run_tests_recurrent_tasks
  check_run_tests_network

  check_run_tests_software
  check_run_tests_containers
  check_run_tests_processes
  # check_run_tests_cves

  check_exit 0
}

[ ! "$check_NO_EXEC" ] && main "$@"
#)
