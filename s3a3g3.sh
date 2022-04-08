#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# s3a3g3.sh - 等保3级基线配置脚本

# Copyright 2022,  <huangqw@huangqingwandeMacBook-Pro.local>
  
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License at <http://www.gnu.org/licenses/> for
# more details.

# Usage: s3a3g3.sh [-h|--help]
#        s3a3g3.sh [-r|--recovery] [-b|--backup] [-a|--apply] [-s|--secure-network]

# Revision history:
# 2022-04-02 Refactoring script. (0.4.2)
# ---------------------------------------------------------------------------

### Terminal settings ###
# set -o errexit # Script exists on first failure, aka set -e
# set -o errtrace # aka set -E
# set -o nounset # Script exists on use nounset variables, aka set -u
# set -o xtrace # For debugging purpose, aka set -x

### Global Variables ###
PROGNAME=${0##*/}
VERSION="0.4.2"
LIBS=     # Insert pathnames of any required external shell libraries here

RESTART_FLAG=1
OS_TYPE='unknow'
OS_VER='unknow'
OS_VER_LIKE='unknow'
OS_PRETTY_NAME='unknow'
# 操作日志
LOG_FILE="$(basename $0 .sh).log"
BASH_HISTORY_SIZE=5
BASH_TMOUT=600
# 备份目录
BACKUP_DIR_NAME="$(basename $0 .sh)-backup"
# 复原命令
RECOVER_COMMANDS="$(basename $0 .sh)-backup/recover_commands.sh"
# 原文件
ORIGIN_FILEPATHS=(
  "/etc/pam.d/system-auth"
  "/etc/pam.d/system-auth-ac"
  "/etc/pam.d/common-password"
  "~/.ssh/authorized_keys"
  "/etc/pam.d/sshd"
  "/etc/sudoers"
  "/etc/ssh/sshd_config"
  "/etc/profile"
  "/etc/bashrc"
  "/etc/csh.cshrc"
  "/etc/csh.login"
  "/etc/pam.d/su"
  "/etc/login.defs"
  "/etc/security/pwquality.conf"
  "/etc/sysctl.conf"
  "/etc/security/limits.conf"
)

# Foreground Colors
RESET="$(tput sgr0)"
FG_BLACK="$(tput setaf 0)"
FG_RED="$(tput setaf 1)"
FG_GREEN="$(tput setaf 2)"
FG_YELLOW="$(tput setaf 3)"
FG_BLUE="$(tput setaf 4)"
FG_MAGENTA="$(tput setaf 5)"
FG_CYAN="$(tput setaf 6)"
FG_WHITE="$(tput setaf 7)"
FG_NOT_USED="$(tput setaf 8)"
FG_DEFAULT="$(tput setaf 9)"

# Background Colors
BG_BLACK="$(tput setab 0)"
BG_RED="$(tput setab 1)"
BG_GREEN="$(tput setab 2)"
BG_YELLOW="$(tput setab 3)"
BG_BLUE="$(tput setab 4)"
BG_MAGENTA="$(tput setab 5)"
BG_CYAN="$(tput setab 6)"
BG_WHITE="$(tput setab 7)"
BG_NOT_USED="$(tput setab 8)"
BG_DEFAULT="$(tput setab 9)"

clean_up() { # Perform pre-exit housekeeping
  return
}

error_exit() {

  local error_message="$1"

  printf "%s: %s\n" "${PROGNAME}" "${error_message:-"Unknown Error"}" >&2
  clean_up
  exit 1
}

graceful_exit() {
  clean_up
  exit
}

signal_exit() { # Handle trapped signals

  local signal="$1"

  case "$signal" in
    INT)
      error_exit "Program interrupted by user" ;;
    TERM)
      error_exit "Program terminated" ;;
    *)
      error_exit "Terminating on unknown signal" ;;
  esac
}

load_libraries() { # Load external shell libraries

  local i

  for i in $LIBS; do
    if [[ -r "$i" ]]; then
      source "$i" || error_exit "Library '$i' contains errors."
    else
      error_exit "Required library '$i' not found."
    fi
  done
}

usage() {
  printf "%s\n" "Usage: ${PROGNAME} [-h|--help]"
  printf "%s\n" "       ${PROGNAME} [-r|--recovery] [-b|--backup] [-a|--apply] [-s|--secure-network]"
}

help_message() {
  cat <<- _EOF_
$PROGNAME ver. $VERSION
等保3级基线配置脚本

$(usage)

  Options:
  -h, --help                  Display this help message and exit.
  -r, --recovery              recover all the changes
  -b, --backup                backup configure files
  -a, --apply                 apply settings
  -s, --secure-network        secure network configuration (firewalld, not support iptables)

  NOTE: You must be the superuser to run this script.

_EOF_
  return
}

log() {
  ###
   # @description: 写日志
   # @param logLevel, msg
   # @return {*}
  ###

  local timeAndDate=$(date +'%Y/%m/%d %H:%M:%S')
  local logLevel="$1"
  local msg="$2"
  
  case "$1" in
    "SUCCESS")
      __output="[${timeAndDate}] [${logLevel}] [${FUNCNAME[1]}] > ${msg}\n"
      printf "${__output}" >> ${LOG_FILE} && printf "${FG_GREEN}${__output}"
      ;;
    "INFO")
      __output="[${timeAndDate}] [${logLevel}] [${FUNCNAME[1]}] > ${msg}\n"
      printf "${__output}" >> ${LOG_FILE} && printf "${FG_CYAN}${__output}"
      ;;
    "WARRN")
      __output="[${timeAndDate}] [${logLevel}] [${FUNCNAME[1]}] > ${msg}\n"
      printf "${__output}" >> ${LOG_FILE} && printf "${FG_YELLOW}${__output}"
      ;;
    "ERROR")
      __output="[${timeAndDate}] [${logLevel}] [${FUNCNAME[1]}] > ${msg}\n"
      printf "${__output}" >> ${LOG_FILE} && printf "${FG_RED}${__output}"
        ;;
    *)
      __output="[${timeAndDate}] [INFO] [${FUNCNAME[1]}] > ${msg}\n"
      printf "${__output}" >> ${LOG_FILE} && printf "${FG_CYAN}${__output}"
      ;;
  esac
}


get_os_type() {
  ###
   # @description: Get OS type
   # @param {*}
   # @return {*}
  ###
  
  log "INFO" "Getting OS type..."
  
  if [ -f "/etc/redhat-release" ]; then
    OS_TYPE=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\1/ip" /etc/redhat-release)
    OS_VER=$(sed -nr "s/^.*([0-9])\.([0-9]).*/\1/ip" /etc/redhat-release)
    OS_PRETTY_NAME=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\1 \2 \3 \4/ip" /etc/redhat-release)
    log "INFO" "Current OS release: ${OS_PRETTY_NAME}"
    if [ ${OS_VER::1} == 6 ] || [ ${OS_VER::1} == 7 ] || [ ${OS_VER::1} == 8 ]; then
      log "SUCCESS" "Supported OS release: ${OS_VER}"
    else
      log "WARRN" "Untested OS release: ${OS_VER}"
      exit 1
    fi
  # elif [ -n "$(command -v lsb_release)" ]; then
  #     distroname=$(lsb_release -s -d)
  else
      log "ERROR" "Failed to detect OS release, please check if it's rhel release, script exits"
      exit 1
  fi
}


restart_ssh(){
  ###
   # @description: restart_ssh
   # @param {*}
   # @return {*}
  ###

  log "WARRN" "Need restart SSH service manully..."
  log "INFO" "Run 'service sshd restart' or 'systemctl restart sshd'"
}

backup(){
  ###
  # @description: 备份文件
  # @param {*}
  # @return {*}
  ###
  
  log "INFO" "Backup files ..."

  if [ ! -d ${BACKUP_DIR_NAME} ]; then
    mkdir ${BACKUP_DIR_NAME}
    for filepath in "${ORIGIN_FILEPATHS[@]}"
    do
      if [ -f ${filepath} ]; then
        filename=$(basename ${filepath})
        cp -a ${filepath} ${BACKUP_DIR_NAME}/${filename}.bak
        if [ $? == 0 ]; then
          log "SUCCESS" "Copy ${filepath} to ${BACKUP_DIR_NAME}/${filename}.bak"
        else
          log "ERROR" "Failed to copy ${filepath} to ${BACKUP_DIR_NAME}/${filename}.bak"
          log "ERROR" "Backup procedure terminated, please check log"
          exit 1
        fi
      else
        log "WARRN" "${filepath} does not exist"
      fi
    done
    if [ ! -f ${RECOVER_COMMANDS} ];then
      touch "${RECOVER_COMMANDS}"
      if [ $? == 0 ]; then
        log "SUCCESS" "Create recover command file"
      fi
    else
      mv "${RECOVER_COMMANDS}" "${RECOVER_COMMANDS}.$(date +'%Y%m%d%H%M%S')"
      log "INFO" "Move ${RECOVER_COMMANDS} to ${RECOVER_COMMANDS}.$(date +'%Y%m%d%H%M%S')"
      touch "${RECOVER_COMMANDS}"
      if [ $? == 0 ]; then
        log "SUCCESS" "Create recover command file"
      fi
    fi
  else
    log "WARRN" "Backup directory already exists..."
    read -p "Overwrite or move to new name ? [m|move (default), o|overwrite, c|cancel] > " selected
    selected=${selected:-move}
    case "${selected}" in
      "o"|"overwrite")
        rm -rf ${BACKUP_DIR_NAME}
        backup
        ;;
      "m"|"move")
        mv "${BACKUP_DIR_NAME}" "${BACKUP_DIR_NAME}-$(date +'%Y%m%d%H%M')"
        backup
        ;;
      "c"|"cancel")
        exit 0
        ;;
      *)
        log "WARRN" "Wrong value (m, o, c)"
        backup
        ;;
    esac
  fi
}

recovery(){
  ###
   # @description: 备份文件还原
   # @param {*}
   # @return {*}
  ###

  log "INFO" "Recovery all..."
  for filepath in "${ORIGIN_FILEPATHS[@]}"
  do
    backup_filepath=${BACKUP_DIR_NAME}/$(basename ${filepath}).bak
    if [ -f ${backup_filepath} ]; then
      cp -a ${backup_filepath} ${filepath}
      if [ $? == 0 ]; then
        log "SUCCESS" "Restore ${backup_filepath} to ${filepath}"
      else
        log "WARRN" "Failed to restore ${backup_filepath} to ${filepath}"
      fi
    else
      log "WARRN" "${backup_filepath} does not exist"
    fi
  done

  bash ${RECOVER_COMMANDS}

  # reset terminal environment
  # source /etc/profile 2>/dev/null
}

password_complexity(){
  ###
   # @description: 口令设置
   # @param {*}
   # @return {*}
  ###
  log "INFO" "Setting password complexity..."

  if [ -f /etc/pam.d/system-auth ];then
    config="/etc/pam.d/system-auth"
  elif [ -f /etc/pam.d/common-password ];then
    config="/etc/pam.d/common-password"
  else
    log "ERROR" "Failed to locate '/etc/pam.d/system-auth' or '/etc/pam.d/common-password'"
    exit 1
  fi

  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(difok=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(minlen=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(ucredit=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(lcredit=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(dcredit=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(ocredit=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)(enforce_for_root\s?)(.*)/\1\2\4/g" ${config} > /dev/null

  sed -ri "s/^(password.*requisite.*pam_.*\.so)(.*)$/\1\2 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root/g" ${config}
  if [ $? == 0 ];then
      log "SUCCESS" "Password complexity: difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root"
  else
      log "ERROR" "Failed to set password complexity..."
      exit 1
  fi

  sed -ri "s/^(password.*sufficient.*pam_unix\.so)(.*)(remember=.?.?\s?)(.*)/\1\2\4/g" ${config} > /dev/null
  sed -ri "s/^(password.*sufficient.*pam_unix\.so)(.*)$/\1\2 remember=6/g" ${config}
  if [ $? == 0 ];then
      log "SUCCESS" "Password repeat times: remember=6"
  else
      log "ERROR" "Failed to set password repeat times..."
      exit 1
  fi

  sed -ri "s/(PASS_MAX_DAYS\s*)([0-9]*)/\190/g" /etc/login.defs
  if [ $? == 0 ] ;then
      log "SUCCESS" "login.defs: set PASS_MAX_DAYS 90"
  else
      log "ERROR" "login.defs: failed to set PASS_MAX_DAYS 90"
  fi

  sed -ri "s/(PASS_MIN_DAYS\s*)([0-9]*)/\16/g" /etc/login.defs
  if [ $? == 0 ] ;then
      log "SUCCESS" "login.defs: set PASS_MIN_DAYS 6"
  else
      log "ERROR" "login.defs: failed to set PASS_MIN_DAYS 6"
  fi

  sed -ri "s/(PASS_MIN_LEN\s*)([0-9]*)/\16/g" /etc/login.defs
  if [ $? == 0 ] ;then
      log "SUCCESS" "login.defs: set PASS_MIN_LEN 6"
  else
      log "ERROR" "login.defs: failed to set PASS_MIN_LEN 6"
  fi

  sed -ri "s/(PASS_WARN_AGE\s*)([0-9]*)/\130/g" /etc/login.defs
  if [ $? == 0 ] ;then
      log "SUCCESS" "login.defs: set PASS_WARN_AGE 30"
  else
      log "ERROR" "login.defs: failed to set PASS_WARN_AGE 30"
  fi
}

add2wheel() {
  ###
  # @description: 添加 superu 用户到 wheel 组
  # @param {*}
  # @return {*}
  ###

  if $(cat /etc/passwd | grep superu > /dev/null);then
    id -Gn superu | grep wheel > /dev/null
    if [ $? != 0 ];then
      if $(usermod -G wheel superu);then
        log "SUCCESS" "Add user superu to wheel group"
      fi
    else
      log "INFO" "User 'superu' is already in wheel group"
    fi
  else
    log "ERROR" "User 'superu' is not exist!"
    exit 1
  fi
}

limit_su(){
  ###
  # @description: 禁止 wheel 组之外用户切换到 root
  # @param {*}
  # @return {*}
  ###
  
  log "INFO" "Limit non-wheel group user su to root..."

  if [ -f /etc/pam.d/su ];then
    sufile="/etc/pam.d/su"
  else
    log "ERROR" "file /etc/pam.d/su doesn't exist"
    log "ERROR" "Failed to limit non-wheel group user su to root"
    exit 1
  fi
  
  if add2wheel;then
    if sed -ri "s/^.*(auth\s*required\s*pam_wheel.so\s*use_uid)$/\1 group=wheel/g" ${sufile}; then
      log "SUCCESS" "require a user to be in the 'wheel' group"
    else
          echo 'auth		required	pam_wheel.so use_uid group=wheel/g' >> ${sufile}
      log "SUCCESS" "require a user to be in the 'wheel' group"
    fi

    if sed -ri "s/^.*(auth\s*sufficient\s*pam_wheel.so\s*trust use_uid)$/\1 group=wheel/g" ${sufile}; then
      log "SUCCESS" "implicitly trust users in the 'wheel' group"
    else
      echo 'auth		sufficient	pam_wheel.so trust use_uid group=wheel/g' >> ${sufile}
      log "SUCCESS" "require a user to be in the 'wheel' group"
    fi
  else
    log "ERROR" "Failed to limit non-wheel group user su to root"
  fi
}

secure_sshd(){
  ###
  # @description: 加固 SSHD 服务
  # @param {*}
  # @return {*}
  ###
  log "INFO" "Secure sshd service..."

  if [ ! -f /etc/ssh/sshd_config ];then
      log "ERROR" "File /etc/ssh/sshd_config does not exist"
      log "ERROR" "Failed to secure sshd service"
      exit 1
  fi

  grep -E '^Protocol' /etc/ssh/sshd_config > /dev/null
  if [ $? == 0 ];then
    sed -i 's/^Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config
    if [ $? != 0 ];then
      log "ERROR" "Failed to set 'Protocol 2' option"
    else
      log "SUCCESS" "Set 'Protocol 2' option"
    fi
  else
    echo 'Protocol 2' >> /etc/ssh/sshd_config
    log "SUCCESS" "Set 'Protocol 2' option"
  fi
  
  grep -E '^PermitRootLogin no$' /etc/ssh/sshd_config > /dev/null
  if [ $? == 1 ];then
    grep -E '(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)' /etc/ssh/sshd_config >/dev/null
    if [ $? == 0 ];then
      sed -i -r 's/(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)/PermitRootLogin no/g' /etc/ssh/sshd_config
      if [ $? != 0 ];then
          log "ERROR" "Failed to set 'PermitRootLogin no'"
      else
          log "SUCCESS" "Successfully set 'PermitRootLogin no'"
          RESTART_FLAG=0
      fi
    else
      echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
      log "SUCCESS" "Successfully set 'PermitRootLogin no'"
      RESTART_FLAG=0
    fi
  else
    log "INFO" "Already disable remote root login"
  fi
}

set_bash_history_tmout(){
  ###
  # @description: 配置历史操作记录以及超时登出
  # @param {*}
  # @return {*}
  ###

  log "INFO" "Set bash timeout & command history size..."

  # history size
  grep -E "^HISTSIZE=" /etc/profile >/dev/null
  if [ $? == 0 ];then
    sed -i "s/^HISTSIZE=.*$/HISTSIZE=${BASH_HISTORY_SIZE}/g" /etc/profile
  else
    echo 'HISTSIZE=${BASH_HISTORY_SIZE}' >> /etc/profile
  fi
  if [ $? == 0 ];then
    log "SUCCESS" "Successfully set 'HISTSIZE=${BASH_HISTORY_SIZE}'"
  fi

  # history format
  grep -E "^export HISTTIMEFORMAT=" /etc/profile > /dev/null
  if [ $? == 0 ];then
    sed -i 's/^export HISTTIMEFORMAT=.*$/export HISTTIMEFORMAT="%F %T `whoami` "/g' /etc/profile
  else
    echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
  fi
  if [ $? == 0 ];then
    log "SUCCESS" "Successfully set HISTTIMEFORMAT to 'Number-Time-User-Command'"
  fi

  #TIME_OUT
  grep -E "^TMOUT=" /etc/profile	> /dev/null
  if [ $? == 0 ];then
    sed -i "s/^TMOUT=.*$/TMOUT=${BASH_TMOUT}/g" /etc/profile
  else
    echo "TMOUT=${BASH_TMOUT}" >> /etc/profile
  fi
  if [ $? == 0 ];then
    log "SUCCESS" "Successfully set 'TMOUNT=${BASH_TMOUT}'"
  fi
}

immutable_user_conf_file() {
  ###
   # @description: 用户相关文件设置 immutable（/etc/gshadow,/etc/passwd,/etc/group,/etc/shadow）
   #               需要注意，该函数应该放在任何有修改用户信息的命令后面，否则用户相关信息操作将不可用
   # @param {*}
   # @return {*}
  ###

  log "INFO" "Immutable user conf file..."

  for file in /etc/gshadow /etc/passwd /etc/group /etc/shadow
  do
    if [ -f ${file} ]; then
      lsattr ${file} | grep -E "^.{4}i" > /dev/null
      if [ $? != 0 ];then
        chattr +i ${file}
        if [ $? == 0 ];then
          log "SUCCESS" "Add immutable attribute to ${file}"
          echo "chattr -i ${file}" >> ${RECOVER_COMMANDS}
        fi
      else
        log "INFO" "Already add immutable attribute to ${file}"
      fi
    else
      log "ERROR" "File '${file}' does not exist"
    fi
  done
}

limit_system_files() {
  ###
   # @description: 重要目录或文件权限设置
   # @param {*}
   # @return {*}
  ###

  log "INFO" "Limit system files..."
  
  # limit rc script
  for file in /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rc.d/init.d
  do
    if [ -d ${file} ] || [ -h ${file} ]; then
      ret=$(stat -c "%a" ${file})
      if [ ${ret} -ne 750 ]; then
        chmod 750 ${file}
        if [ $? == 0 ]; then
          log "SUCCESS" "${file} permissions changed to 750"
          echo "chmod ${ret} ${file}" >> ${RECOVER_COMMANDS}
        fi
      elif [ ${ret} -eq 750 ]; then
        log "INFO" "${file} permissions already set to 750"
      fi
    else
      log "ERROR" "${file} does not exist"
    fi
  done

  # limit 
  for file in /etc/security /etc/shadow 
  do
    if [ -f ${file} ] || [ -d ${file} ]; then
      ret=$(stat -c "%a" ${file})
      if [ ${ret} -ne 600 ]; then
        chmod 600 ${file}
        if [ $? == 0 ]; then
          log "SUCCESS" "${file} permissions changed to 600"
          echo "chmod ${ret} ${file}" >> ${RECOVER_COMMANDS}
        fi
      elif [ ${ret} -eq 600 ]; then
        log "INFO" "${file} permissions already set to 600"
      fi
    else
      log "ERROR" "${file}' not exist"
    fi
  done

  # limit
  for file in /etc/group /etc/services
  do
    if [ -f ${file} ]; then
      ret=$(stat -c "%a" ${file})
      if [ ${ret} -ne 644 ]; then
        chmod 644 ${file}
        if [ $? == 0 ]; then
          log "SUCCESS" "${file} permissions changed to 644"
          echo "chmod ${ret} ${file}" >> ${RECOVER_COMMANDS}
        fi
      elif [ ${ret} -eq 644 ]; then
        log "INFO" "${file} permissions already set to 644"
      fi
    else
      log "ERROR" "${file}' not exist"
    fi
  done

  # limit
  for file in /etc/grub.conf /boot/grub/grub.conf /etc/lilo.conf /etc/grub2.cfg /boot/grub2/grub.cfg
  do
    if [ -f ${file} ] && [ ! -L ${file} ]; then
      ret=$(stat -c "%a" ${file})
      echo "chmod ${ret} ${file}" >> ${RECOVER_COMMANDS}
      if chmod 600 ${file}; then
        log "SUCCESS" "Successfully chmod 600 ${file}"
      else
        log "ERROR" "Failed to chmod 600 ${file}"
      fi
    else
      log "WARRN" "${file} does not exist or is not hard link file"
    fi
  done
}

umask_profile() {
  ###
   # @description: 用户 umask 设置
   # @param {*}
   # @return {*}
  ###

  log "INFO" "Set user umask..."

  for file in /etc/bashrc /etc/csh.cshrc /etc/profile /etc/csh.login /etc/login.defs
  do
    if [ -f ${file} ]; then
      # grep -v '^#' ${file} | grep -i -E 'umask.*.[0-9]{3}' > /dev/null

      # \1 means captured group
      sed -i -r 's/(umask.*)[0-9]{3}$/\1077/Ig' ${file}
      if [ $? == 0 ]; then
          log "SUCCESS" "${file} set 'umask 077'"
      else
          log "ERROR" "${file} failed to set 'umask 077'"
      fi
    else
      log "ERROR" "${file} does not exist"
    fi
  done
}

drop_risky_file() {
  ###
  # @description: 删除潜在的危险文件 .netrc, hosts.equiv, .rhosts
  # @param {*}
  # @return {*}
  ###

  log "INFO" "Drop risky files..."
  for file in $(find / -maxdepth 3 \( -name .netrc -or -name hosts.equiv -or -name .rhosts \) 2>/dev/null | xargs)
  do
    mv "${file}" "${file}.bak"
    log "SUCCESS" "Move ${file} to ${file}.bak"
  done
}

disable_telnet_login() {
  ###
  # @description: 禁止使用 telnet 远程登陆
  # @param {*}
  # @return {*}
  ###   
  if rpm -qa | grep telnet-server; then
    if [ -f /etc/xinetd.d/telnet ]; then
      sed -r "s/(disable.*= ).*$/\1yes/Ig" /etc/xinetd.d/telnet
      if [[ $? == 0 ]];then
          log "SUCCESS" "Set /etc/xinetd.d/telnet option 'disable = yes'"
      else
          log "ERROR" "Failed to set /etc/xinetd.d/telnet option 'disable = yes'"
      fi
      if rpm -qa | grep xinetd; then
        case ${OS_VER} in
          7)
           systemctl restart xinetd
           ;;
          6)
           service xinetd restart
           ;;
          *)
           log "WARRN" "Failed to restart xinetd"
        esac
      fi
    else
      log "INFO" "/etc/xinetd.d/telnet does not exist"
    fi
  else
    log "INFO" "telnet-server is not installed"
  fi
}

drop_centos_user() {
  ###
   # @description: 删除图形化安装系统时创建的 centos 用户
   # @param {*}
   # @return {*}
  ###
  if $(cat /etc/passwd | grep centos > /dev/null); then
    # temporary remove immutable attr
    chattr -i /etc/passwd /etc/group /etc/gshadow /etc/shadow
    if $(userdel -r centos); then
      log "SUCCESS" "Delete user 'centos'"
    else
      log "ERROR" "Could not delete user 'centos'"
    fi
  else
    log "INFO" "'centos' user does not exist, no need to delete"
  fi
  
}

configure_kernel_parameters() {
  ###
   # @description: 修改内核参数
   # @param {*}
   # @return {*}
  ###    
  FILE="/etc/sysctl.conf"
  if [ -f ${FILE} ]; then
    sed -ri "s/^(net.ipv4.conf.all.send_redirects.*)//g" ${FILE}
    if echo "net.ipv4.conf.all.send_redirects=0" >> ${FILE}; then
        log "SUCCESS" "set kernel net.ipv4.conf.all.send_redirects=0"
    fi
    
    sed -ri "s/^(net.ipv4.conf.all.accept_redirects.*)//g" ${FILE}
    if echo "net.ipv4.conf.all.accept_redirects=0" >> ${FILE}; then
        log "SUCCESS" "set kernel net.ipv4.conf.all.accept_redirects=0"
    fi
    if /sbin/sysctl -p >/dev/null 2>&1; then
        log "SUCCESS" "Successfully load kernel parameters"
    else
        log "ERROR" "Failed to load kernel parameters"
    fi
  else
    log "WARRN" "${FILE} does not exist"
  fi
}

configure_pam_limis () {
  ###
   # @description: 修改 pam_limits 参数
   # @param {*}
   # @return {*}
  ###    
  FILE="/etc/security/limits.conf"
  if [ -f ${FILE} ]; then
    if grep -E "\*\s*soft\s*core\s*[0-9]*" ${FILE} >/dev/null; then
      sed -ri "s/.*(\*\s*soft\s*core\s*)([0-9]*)/\10/g" ${FILE}
      log "SUCCESS" "Successfully to set soft limits"
    else
      echo "*               soft    core            0" >> ${FILE}
      log "SUCCESS" "Successfully to set soft limits"
    fi

    if grep -E "\*\s*hard\s*core\s*[0-9]*" ${FILE} >/dev/null; then
      sed -ri "s/.*(\*\s*hard\s*core\s*)([0-9]*)/\10/g" ${FILE}
      log "SUCCESS" "Successfully to set hard limits"
    else
      echo "*               hard    core            0" >> ${FILE}
      log "SUCCESS" "Successfully to set hard limits"
    fi
  else
    log "WARRN" "${FILE} does not exist"
  fi
}

secure_logging_file() {
  ###
   # @description: 加固日志文件
   # @param {*}
   # @return {*}
  ###
  lsattr /var/log/messages | grep "^.*a.*\s/var/log/messages$" > /dev/null
  if [ $? == 0 ]; then
    log "INFO" "/var/log/messages already has 'a' attribute"
  else
    chattr +a /var/log/messages > /dev/null
    if [ $? == 0 ]; then
      log "SUCCESS" "Successfully add 'a' attribute to /var/log/messages"
      echo "chattr -a /var/log/messages" >> ${RECOVER_COMMANDS}
    else
      log "ERROR" "Failed to add 'a' attribute to /var/log/messages"
    fi
  fi

  lsattr /etc/logrotate.conf | grep "^.*i.*\s/etc/logrotate.conf$" > /dev/null
  if [ $? == 0 ]; then
    log "INFO" "/etc/logrotate.conf already has 'i' attribute"
  else
    chattr +i /etc/logrotate.conf > /dev/null
    if [ $? == 0 ]; then
      log "SUCCESS" "Successfully add 'i' attribute to /etc/logrotate.conf"
      echo "chattr -i /etc/logrotate.conf" >> ${RECOVER_COMMANDS}
    else
      log "ERROR" "Failed to add 'i' attribute to /etc/logrotate.conf"
    fi
  fi
}

secure_network() {
  ###
  # @description: 主机防火墙配置，限制 ssh 登录白名单，主机禁 ping
  # @param {*}
  # @return {*}
  ### 

  # ssh whitelist
  local ssh_whitelist=(
    "172.16.3.40"
    "172.16.3.43"
    "192.101.109.80"
    "192.101.109.74"
  )
  
  # ping whitelist 
  local ping_whitelist=(
    "172.16.3.40/30"
    "172.16.7.108"
    "192.101.109.64/27"
  )

  # detect whether firewalld is running
  if [ ${OS_VER} == 6 ]; then
    log "WARRN" "Not support iptables, please configure firewall manully!"
  elif [ ${OS_VER} == 7 ] || [ ${OS_VER} == 8 ]; then
    local firewalld_running_status=$(firewall-cmd --state)
    case ${firewalld_running_status} in
      "running")
        # add ssh whitelist rich rules to the public zone
        declare -i local priority_value=-10000
        declare local rule=""
        declare local is_enabled=""
        if [ ${#ssh_whitelist[@]} -gt 0 ]
        then
          for ip in "${ssh_whitelist[@]}"
          do
            rule="rule priority='${priority_value}' family='ipv4' source address='${ip}' service name='ssh' accept"
            is_enabled=$(firewall-cmd --query-rich-rule="${rule}")
            if [ ${is_enabled} == 'yes' ]; then
              log "WARRN" "Rules already enabled: ${rule}"
            else
              firewall-cmd --permanent --add-rich-rule="${rule}" > /dev/null
              if [ $? == 0 ]; then
                log "SUCCESS" "Successfully add rich rule: ${rule}"
              else
                log "ERROR" "Failed to add rich rule: ${rule}"
              fi
            fi
            priority_value=${priority_value}+1000
          done
        fi

        # confirm whether add 192.101.109.0/24 subnet to ssh whitelist or not
        local __confirm='*'
        until [[ ${__confirm} == 'y' || ${__confirm} == 'Y' || ${__confirm} == 'n' || ${__confirm} == 'N' ]]
        do
          read -p "是否添加部门网段(192.101.109.0/24)为 SSH 白名单？ y/n: " __confirm
          case ${__confirm} in
            "y"|"Y")
              rule="rule priority='-100' family='ipv4' source address='192.101.109.0/24' service name='ssh' accept"
              firewall-cmd --permanent --add-rich-rule="${rule}" > /dev/null
              if [ $? == 0 ]; then
                log "SUCCESS" "Successfully add rich rule: ${rule}"
              else
                log "ERROR" "Failed to add rich rule: ${rule}"
              fi
              ;;
            "n"|"N")
              ;;
            *)
              printf "${FG_RED}输入错误: ${__confirm}\n"
              ;;
          esac
        done

        # add ping whitelist to the public zone
        if [ ${#ping_whitelist[@]} -gt 0 ]
        then
          for ip in "${ping_whitelist[@]}"
          do
            rule="rule priority='${priority_value}' family='ipv4' source address='${ip}' protocol value='icmp' accept"
            is_enabled=$(firewall-cmd --query-rich-rule="${rule}")
            if [ ${is_enabled} == 'yes' ]; then
              log "WARRN" "Rules already enabled: ${rule}"
            else
              firewall-cmd --permanent --add-rich-rule="${rule}" > /dev/null
              if [ $? == 0 ]; then
                log "SUCCESS" "Successfully add rich rule: ${rule}"
              else
                log "ERROR" "Failed to add rich rule: ${rule}"
              fi
            fi
            priority_value=${priority_value}+1000
          done
        fi

        # disable icmp ping by default
        rule="rule priority=500 protocol value='icmp' drop"
        is_enabled=$(firewall-cmd --query-rich-rule="${rule}")
        if [ ${is_enabled} == 'yes' ]; then
          log "WARRN" "Rules already enabled: ${rule}"
        else
          firewall-cmd --permanent --add-rich-rule="${rule}" > /dev/null
          if [ $? == 0 ]; then
            log "SUCCESS" "Successfully add rich rule: ${rule}"
          else
            log "ERROR" "Failed to add rich rule: ${rule}"
          fi
        fi

        # remove all sources from the truested zone
        trusted_sources=($(firewall-cmd --zone=trusted --list-sources)) # use () convert string to array
        if [ $? == 0 ] && [ ${#trusted_sources[@]} -gt 0 ]; then
          # loop trusted_sources array
          for source in "${trusted_sources[@]}"
          do
            firewall-cmd --permanent --zone=trusted --remove-source=${source} > /dev/null
            if [ $? == 0 ]; then 
              log "SUCCESS" "Successfully remove source: ${source}"
            else
              log "ERROR" "Failed to remove source: ${source}"
            fi
          done
        fi
        
        # remove ssh service from the trusted zone
        trusted_services=($(firewall-cmd --zone=trusted --list-services)) # use () convert string to array
        if [ $? == 0 ] && [ ${#trusted_services[@]} -gt 0 ]; then
          # loop trusted_services array
          for service in "${trusted_services[@]}"
          do
            firewall-cmd --permanent --zone=trusted --remove-service=${service} > /dev/null
            if [ $? == 0 ]; then 
              log "SUCCESS" "Successfully remove service: ${service}"
            else
              log "ERROR" "Failed to remove service: ${service}"
            fi
          done
        fi

        # remove ssh service from public zone
        is_ssh_enabled=$(firewall-cmd --query-service=ssh)
        if [ ${is_ssh_enabled} == 'yes' ]; then
          firewall-cmd --permanent --remove-service=ssh > /dev/null
          if [ $? == 0 ]; then 
            log "SUCCESS" "Successfully remove service: ssh"
          else
            log "ERROR" "Failed to remove service: ssh"
          fi
        fi

        # reload firewalld rules
        firewall-cmd --reload > /dev/null
        if [ $? == 0 ]; then 
          log "SUCCESS" "Successfully reload rules"
        else
          log "ERROR" "Failed to reload rules"
        fi
        ;;
      "not running")
        log "WARRN" "Firewalld is not running."
        ;;
      *)
        log "WARRN" "Unknown error."
        ;;
    esac
  fi
}

# Trap signals
trap 'tput sgr0' ERR exit
trap "signal_exit TERM" TERM HUP
trap "signal_exit INT"  INT

# Check for root UID
if [[ $(id -u) != 0 ]]; then
  error_exit "You must be the superuser to run this script."
fi
load_libraries

# Parse command-line
while [[ -n "$1" ]]; do
  case "$1" in
    -h | --help)
      help_message
      graceful_exit
      ;;
    -r | --recovery)
      get_os_type
      recovery
      ;;
    -b | --backup)
      get_os_type
      backup
      ;;
    -a | --apply)
      get_os_type
      backup
      drop_centos_user
      password_complexity
      limit_su
      secure_sshd
      set_bash_history_tmout
      limit_system_files
      umask_profile
      immutable_user_conf_file
      drop_risky_file
      disable_telnet_login
      configure_kernel_parameters
      configure_pam_limis
      secure_logging_file
      secure_network
      ;;
    -s | --secure-network)
      get_os_type
      secure_network
      ;;
    --* | -*)
      usage >&2
      error_exit "Unknown option $1"
      ;;
    *)
      printf "Processing argument %s...\n" "$1"
      ;;
  esac
  shift
done

# Main logic

graceful_exit