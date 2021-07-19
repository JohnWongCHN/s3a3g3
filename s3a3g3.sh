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
 # @LastEditTime: 2021-07-19 21:28:29
 # @FilePath: /s3a3g3/s3a3g3.sh
 # @Desc: Description
 # @Version: v0.2
###

### Terminal settings ###
set -o errexit # Script exists on first failure, aka set -e
# set -o undeclared # Script exists on use undeclared variables, aka set -u
set -u
set -o xtrace # For debugging purpose, aka set -x

### Global Variables ###
declare SCRIPT_VERSION='v0.2'
declare RESTART_FLAG=1
declare OS_TYPE='unknow'
declare OS_VER='unknow'
declare OS_VER_LIKE='unknow'
declare OS_PRETTY_NAME='unknow'
# 操作日志
declare LOG_FILE="$(basename $0 .sh).log"
declare BASH_HISTORY_SIZE=10000
declare BASH_TMOUT=600
# 备份目录
declare BACKUP_DIR_NAME="$(basename $0 .sh)-backup"
# 复原命令
declare RECOVER_COMMANDS="$(basename $0 .sh)-backup/recover_commands.sh"
# 临时文件
declare TMPFILE=$(mktemp)
# 原文件
declare -a ORIGIN_FILEPATHS=(
    "/etc/pam.d/system-auth"
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
    # elif [ -f "/etc/debian_version" ]; then
    #     distroname="Debian $(cat /etc/debian_version)"
    elif [ -f "/etc/redhat-release" ]; then
        OS_TYPE=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\1/ip" /etc/redhat-release)
        OS_VER=$(sed -nr "s/^(.*) (release) (.*) \((.*)\)/\3/ip" /etc/redhat-release)
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
            fi
        done
    else
        log "WARRN" "Backup directory already exists, to aviod overwriting, script exists"
        exit 1
    fi

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

    # reset terminal environment
    source /etc/profile
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

    grep -E "^password.*requisite.*pam_cracklib.so" ${config}  > /dev/null
    if [ $? == 0 ];then
        sed -i "s/^password.*requisite.*pam_cracklib\.so.*$/password    requisite       pam_cracklib.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" ${config}
        log "SUCCESS" "Password complexity: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5"
    else
        grep -E "pam_pwquality\.so" ${config} > /dev/null
        if [ $? == 0 ];then
            sed -i "s/password.*requisite.*pam_pwquality\.so.*$/password     requisite       pam_pwquality.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" ${config}
            log "SUCCESS" "Password complexity: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5"
        else
            echo 'password      requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5' >> ${config}
            log "SUCCESS" "Password complexity: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5"
        fi
    fi

    grep -E '^PASS_MAX_DAYS.*90' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g" /etc/login.defs
        if [ $? == 0 ] ;then
            log "SUCCESS" "login.defs: set PASS_MAX_DAYS 90"
        else
            log "ERROR" "login.defs: failed to set PASS_MAX_DAYS 90"
        fi
    else
        log "INFO" "login.defs: already set PASS_MAX_DAYS 90"
    fi

    grep -E '^PASS_MIN_DAYS.*6' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 6/g" /etc/login.defs
        if [ $? == 0 ] ;then
            log "SUCCESS" "login.defs: set PASS_MIN_DAYS 6"
        else
            log "ERROR" "login.defs: failed to set PASS_MIN_DAYS 6"
        fi
    else
        log "INFO" "login.defs: already set PASS_MIN_DAYS 6"
    fi

    grep -E '^PASS_WARN_AGE.*30' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE 30/g" /etc/login.defs
        if [ $? == 0 ] ;then
            log "SUCCESS" "login.defs: set PASS_WARN_AGE 30"
        else
            log "ERROR" "login.defs: failed to set PASS_WARN_AGE 30"
        fi
    else
        log "INFO" "login.defs: already set PASS_WARN_AGE 30"
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
        egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*$" > /dev/null
        if [ $? == 0 ];then
            egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*group=wheel" > /dev/null
            if [ $? == 0 ];then
                log "INFO" "Already limit non-wheel group user su to root"
            else
                sed -i 's/^auth.*required.*pam_wheel.so.*$/& group=wheel/g' ${sufile}
            fi
        else
            echo 'auth		required	pam_wheel.so group=wheel' >> ${sufile}
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
    source /etc/profile
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
            ret=`stat -c "%a" ${file}`
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
            ret=`stat -c "%a" ${file}`
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
            ret=`stat -c "%a" ${file}`
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
            grep -v '^#' ${file} | grep -i -E 'umask.*.[0-9]{3}' > /dev/null
            if [ $? != 0 ]; then
                # \1 means captured group
                sed -i -r 's/(umask.*)[0-9]{3}$/\1077/Ig' ${file}
                if [ $? == 0 ]; then
                    log "SUCCESS" "${file} set 'umask 077'"
                fi
            else
                log "INFO" "${file} already set 'umask 077'"
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

function version() {
    ###
    # @description: 打印版本信息
    # @param {*}
    # @return {*}
    ###    

    printf "@Author: John Wong"
    printf "@Desc: 等保3级，基线配置脚本"
    printf "@Version: ${SCRIPT_VERSION}"

}

function main(){
    ###
     # @description: main function
     # @param {*}
     # @return {*}
    ###

    # Save screen
    tput smcup

    # Display menu until selection == 0
    while [[ $REPLY != 0 ]]; do
      echo -n ${BG_BLUE}${FG_WHITE}
      clear

cat << EOF
Please Select:

    1: All protective
    2: Restore files
    v: Print version
    0: Quit
EOF

      read -p "Enter selection [0-2] > " selection

      # Clear area beneath menu
      tput cup 10 0
      echo -n ${BG_BLACK}${FG_GREEN}
      tput ed
      tput cup 11 0

      # Act on selection
      case $selection in
        1)
            get_os_type
            backup
            password
            limit_su
            remote_login
            set_bash_history_tmout
            limit_system_files
            umask_profile
            immutable_user_conf_file
            restart_ssh
            ;;
        2)  
            restore
            ;;
        v)  
            version
            ;;
        0)  
            break
            ;;
        *)  
            echo "Invalid entry."
            ;;
      esac
      printf "\n\nPress any key to continue."
      read -n 1
    done

    # Restore screen
    tput rmcup
    echo "Program terminated."

}


### main entry
trap 'rm ${TMPFILE}' err exit
trap recover err exit
main