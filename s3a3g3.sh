#!/bin/bash
###
 # 
 # 　　┏┓　　　┏┓+ +
 # 　┏┛┻━━━┛┻┓ + +
 # 　┃　　　　　　　┃ 　
 # 　┃　　　━　　　┃ ++ + + +
 #  ████━████ ┃+
 # 　┃　　　　　　　┃ +
 # 　┃　　　┻　　　┃
 # 　┃　　　　　　　┃ + +
 # 　┗━┓　　　┏━┛
 # 　　　┃　　　┃　　　　　　　　　　　
 # 　　　┃　　　┃ + + + +
 # 　　　┃　　　┃
 # 　　　┃　　　┃ +  神兽保佑
 # 　　　┃　　　┃    代码无bug　　
 # 　　　┃　　　┃　　+　　　　　　　　　
 # 　　　┃　 　　┗━━━┓ + +
 # 　　　┃ 　　　　　　　┣┓
 # 　　　┃ 　　　　　　　┏┛
 # 　　　┗┓┓┏━┳┓┏┛ + + + +
 # 　　　　┃┫┫　┃┫┫
 # 　　　　┗┻┛　┗┻┛+ + + +
 # 
 # 
 # @Author: John Wong
 # @Date: 2021-06-01 11:34:15
 # @LastEditors: John Wong
 # @LastEditTime: 2021-07-21 16:51:15
 # @FilePath: /s3a3g3/s3a3g3.sh
 # @Desc: Description
 # @Version: v0.3
###

### Terminal settings ###
#set -o errexit # Script exists on first failure, aka set -e
#set -o errtrace # aka set -E
set -o nounset # Script exists on use nounset variables, aka set -u
# set -o xtrace # For debugging purpose, aka set -x

### Global Variables ###
declare readonly SCRIPT_VERSION='v0.3'
declare RESTART_FLAG=1
declare OS_TYPE='unknow'
declare OS_VER='unknow'
declare OS_VER_LIKE='unknow'
declare OS_PRETTY_NAME='unknow'
# 操作日志
declare LOG_FILE="$(basename $0 .sh).log"
declare readonly BASH_HISTORY_SIZE=10000
declare readonly BASH_TMOUT=600
# 备份目录
declare readonly BACKUP_DIR_NAME="$(basename $0 .sh)-backup"
# 复原命令
declare readonly RECOVER_COMMANDS="$(basename $0 .sh)-backup/recover_commands.sh"
# 原文件
declare -a readonly ORIGIN_FILEPATHS=(
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

function log() {
    ###
     # @description: 写日志
     # @param logLevel, msg
     # @return {*}
    ###

    # Foreground Colors
    declare local RESET="$(tput sgr0)"
    declare local FG_BLACK="$(tput setaf 0)"
    declare local FG_RED="$(tput setaf 1)"
    declare local FG_GREEN="$(tput setaf 2)"
    declare local FG_YELLOW="$(tput setaf 3)"
    declare local FG_BLUE="$(tput setaf 4)"
    declare local FG_MAGENTA="$(tput setaf 5)"
    declare local FG_CYAN="$(tput setaf 6)"
    declare local FG_WHITE="$(tput setaf 7)"
    declare local FG_NOT_USED="$(tput setaf 8)"
    declare local FG_DEFAULT="$(tput setaf 9)"

    # Background Colors
    declare local BG_BLACK="$(tput setab 0)"
    declare local BG_RED="$(tput setab 1)"
    declare local BG_GREEN="$(tput setab 2)"
    declare local BG_YELLOW="$(tput setab 3)"
    declare local BG_BLUE="$(tput setab 4)"
    declare local BG_MAGENTA="$(tput setab 5)"
    declare local BG_CYAN="$(tput setab 6)"
    declare local BG_WHITE="$(tput setab 7)"
    declare local BG_NOT_USED="$(tput setab 8)"
    declare local BG_DEFAULT="$(tput setab 9)"

    timeAndDate=$(date +'%Y/%m/%d %H:%M:%S')
    logLevel="$1"
    msg="$2"
    
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

# function center() {
#     ###
#      # @description: 居中输出字符
#      # @param {*}
#      # @return {*}
#     ###    
#     term_width="$(tput cols)"
#     # padding="$(printf '%0.1s' =)"
#     padding="="
#     printf '%-*s %s %*s\n' "$(((term_width-2-${#1})/2))" "$padding" "$1" "$(((term_width-1-${#1})/2))" "$padding"
# }

function get_os_type() {
    ###
     # @description: Get OS type
     # @param {*}
     # @return {*}
    ###
    
    log "INFO" "Getting OS type..."
    
    if [ -f "/etc/os-release" ]; then
        # freedesktop.org and systemd
        . /etc/os-release
        OS_TYPE=${NAME}
        OS_VER=${VERSION_ID}
        OS_VER_LIKE=${ID_LIKE}
        OS_PRETTY_NAME=${PRETTY_NAME}
        log "INFO" "Current OS release: ${OS_PRETTY_NAME}"
        if [[ "${OS_VER_LIKE}" =~ "rhel" ]]; then
            if [ ${OS_VER} == 6 ] || [ ${OS_VER} == 7 ]; then
                log "SUCCESS" "Supported OS release: ${OS_VER}"
            else
                log "WARRN" "Untested OS release: ${OS_VER}"
                exit 1
            fi
        else
            log "ERROR" "Unsupported OS release, script exists"
            exit 1
        fi
    elif [ -f "/etc/redhat-release" ]; then
        OS_TYPE=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\1/ip" /etc/redhat-release)
        OS_VER=$(sed -nr "s/^.*([0-9])\.([0-9]).*/\1/ip" /etc/redhat-release)
        OS_PRETTY_NAME=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\1 \2 \3 \4/ip" /etc/redhat-release)
        log "INFO" "Current OS release: ${OS_PRETTY_NAME}"
        if [ ${OS_VER} == 6 ] || [ ${OS_VER} == 7 ]; then
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


function restart_ssh(){
    ###
     # @description: restart_ssh
     # @param {*}
     # @return {*}
    ###

    log "WARRN" "Need restart SSH service manully..."
    log "INFO" "Run 'service sshd restart' or 'systemctl restart sshd'"
}

function backup(){
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

function recovery(){
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

function password_complexity(){
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

function add2wheel() {
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

function limit_su(){
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

function secure_sshd(){
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

function set_bash_history_tmout(){
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

function immutable_user_conf_file() {
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

function limit_system_files() {
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

function umask_profile() {
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

function drop_risky_file() {
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

function disable_telnet_login() {
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

function drop_centos_user() {
    ###
     # @description: 删除图形化安装系统时创建的 centos 用户
     # @param {*}
     # @return {*}
    ###
    if $(cat /etc/passwd | grep centos > /dev/null); then
        if $(userdel -r centos); then
            log "SUCCESS" "Delete user 'centos'"
        else
            log "ERROR" "Could not delete user 'centos'"
        fi
    else
        log "INFO" "'centos' user does not exist, no need to delete"
    fi
    
}

function configure_kernel_parameters() {
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

function configure_pam_limis () {
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

function help() {
    ###
     # @description: 打印脚本帮助
     # @param {*}
     # @return {*}
    ###    
    declare readonly info=$(cat <<EOF
等保3级基线配置脚本 - by John Wong (john-wong@outlook.com)

version: ${SCRIPT_VERSION}

Usage: s3a3g3.sh [-hrba]

Options:
  -h,--help           : this help
  -r,--recovery       : recover all the changes
  -b,--backup         : backup configure files
  -a,--apply          : apply settings
EOF
)
    printf "${info}\n\n"
}

### trap
trap 'tput sgr0' ERR exit
trap 'recovery' ERR

if [ $# -ne 1 ]; then
    help
    exit 1
fi

case $1 in
    "-h"| "--help")
        help
        ;;
    "-r"|"--recovery")
        get_os_type
        recovery
        ;;
    "-b"|"--backup")
        get_os_type
        backup
        ;;
    "-a"|"--apply")
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
        ;;
    *)
        help
        ;;
esac