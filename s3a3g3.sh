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
 # @LastEditTime: 2021-06-30 15:42:45
 # @FilePath: /s3a3g3/s3a3g3.sh
 # @Desc: Description
 # @Version: v0.1
###


### Global Variables ###
RESTART_FLAG=1
OSTYPE='unknow'
# 操作日志
LOGFILE=s3a3g3.log
BASH_HISTORY_SIZE=10000
BASH_TMOUT=600
# 备份目录
BACKUP_DIR_NAME=s3a3g3_backup
# 原备份文件
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

function center() {
    ###
     # @description: 居中输出字符
     # @param {*}
     # @return {*}
    ###    
    term_width="$(tput cols)"
    # padding="$(printf '%0.1s' =)"
    padding="="
    printf '%-*s %s %*s\n' "$(((term_width-2-${#1})/2))" "$padding" "$1" "$(((term_width-1-${#1})/2))" "$padding"
}

function get_os_type() {
    ###
     # @description: Get OS type
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 获取操作系统类型
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    if [ -f /etc/redhat-release ];then
        grep -i 'CentOS' /etc/redhat-release > /dev/null
        if [ $? == 0 ];then
            OSTYPE='CentOS'
        fi
        grep -i 'Redhat' /etc/redhat-release > /dev/null
        if [ $? == 0 ];then
            OSTYPE='Redhat'
        fi
    fi

    if [ -f /etc/centos-release ];then
        grep -i 'Centos' /etc/centos-release > /dev/null
        if [ $? == 0 ];then
            OSTYPE='Centos'
        fi
    fi
    echo -e "${FG_CYAN}[Info]: OSTYPE is ${OSTYPE} ${FG_DEFAULT}" | tee -a ${LOGFILE}
}


function restart_ssh(){
    ###
     # @description: restart_ssh
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 重启 OpenSSH 服务
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    echo -e "${FG_CYAN}[Info]: Please restart SSH service manully \n ('service sshd restart' or 'systemctl restart sshd'). ${FG_DEFAULT}" | tee -a ${LOGFILE}
}

function backup(){
    ###
    # @description: 备份文件
    # @param {*}
    # @return {*}
    ###
__output="
########################
# 备份配置文件
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    if [ ! -d ${BACKUP_DIR_NAME} ]; then
        mkdir ${BACKUP_DIR_NAME}
        for filepath in "${ORIGIN_FILEPATHS[@]}"
        do
            if [ -f ${filepath} ]; then
                filename=`echo ${filepath} | awk -F '/' '{print $NF}'`
                cp -a ${filepath} ${BACKUP_DIR_NAME}/${filename}.bak
                if [ $? == 0 ]; then
                    echo -e "${FG_GREEN}[Success]: Backup ${filepath} to ${BACKUP_DIR_NAME}/${filename}.bak ${FG_DEFAULT}" | tee -a ${LOGFILE}
                else
                    echo -e "${FG_RED}[Error]: Failed to backup ${filepath} to ${BACKUP_DIR_NAME}/${filename}.bak ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            fi
        done
    else
        echo -e "${FG_CYAN}[Info]: Backup file already exist, to avoid overwriting these\n  files, backup will not perform again ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi
}

function restore(){
    ###
     # @description: 备份文件还原
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 恢复配置文件
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    for filepath in "${ORIGIN_FILEPATHS[@]}"
    do
        backup_filepath=${BACKUP_DIR_NAME}/`echo ${filepath} | awk -F '/' '{print $NF}'`.bak
        if [ -f ${backup_filepath} ]; then
            # filename=`echo ${filepath} | awk -F '/' '{print $NF}'`
            cp -a ${backup_filepath} ${filepath}
            if [ $? == 0 ]; then
                echo -e "${FG_GREEN}[Success]: Restore ${backup_filepath} to ${filepath} ${FG_DEFAULT}" | tee -a ${LOGFILE}
            else
                echo -e "${FG_RED}[Error]: Failed to restore ${backup_filepath} to ${filepath} ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        fi
    done

    source /etc/profile
    RESTART_FLAG=0
}

function password(){
    ###
     # @description: 口令设置
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 密码复杂度/密码有效期设置
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    if [ -f /etc/pam.d/system-auth ];then
        config="/etc/pam.d/system-auth"
    elif [ -f /etc/pam.d/common-password ];then
        config="/etc/pam.d/common-password"
    else
        echo -e "${FG_RED}[Error]: Doesn't support this OS. ${FG_DEFAULT}" | tee -a ${LOGFILE}
        return 1
    fi

    grep -E "^password.*requisite.*pam_cracklib.so" $config  > /dev/null
    if [ $? == 0 ];then
        sed -i "s/^password.*requisite.*pam_cracklib\.so.*$/password    requisite       pam_cracklib.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" $config
	    echo -e "${FG_CYAN}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${FG_DEFAULT}" | tee -a ${LOGFILE}
    else
        grep -E "pam_pwquality\.so" $config > /dev/null
        if [ $? == 0 ];then
            sed -i "s/password.*requisite.*pam_pwquality\.so.*$/password     requisite       pam_pwquality.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" $config
	        echo -e "${FG_CYAN}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${FG_DEFAULT}" | tee -a ${LOGFILE}
        else
            echo 'password      requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5' >> $config
	        echo -e "${FG_CYAN}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    fi

    if [ $? == 0 ];then
        echo -e "${FG_GREEN}[Success]: Password complexity set successed ${FG_DEFAULT}" | tee -a ${LOGFILE}
    else
        echo -e "${FG_RED}[Error]: Password complexity set failed ${FG_DEFAULT}" | tee -a ${LOGFILE}
	    exit 1
    fi

    grep -E '^PASS_MAX_DAYS.*90' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g" /etc/login.defs
        if [ $? == 0 ] ;then
            echo -e "${FG_GREEN}[Success]: /etc/login.defs set to 'PASS_MAX_DAYS 90' ${FG_DEFAULT}" | tee -a ${LOGFILE}
        else
            echo -e "${FG_RED}[Error]: /etc/login.defs set to 'PASS_MAX_DAYS 90' failed ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    else
        echo -e "${FG_CYAN}[Info]: /etc/login.defs already set 'PASS_MAX_DAYS 90' ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi

    grep -E '^PASS_MIN_DAYS.*6' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 6/g" /etc/login.defs
        if [ $? == 0 ] ;then
            echo -e "${FG_GREEN}[Success]: /etc/login.defs set to 'PASS_MIN_DAYS 6' ${FG_DEFAULT}" | tee -a ${LOGFILE}
        else
            echo -e "${FG_RED}[Error]: /etc/login.defs set to 'PASS_MIN_DAYS 6' failed ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    else
        echo -e "${FG_CYAN}[Info]: /etc/login.defs already set 'PASS_MIN_DAYS 6' ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi


}

function add2wheel() {
    ###
    # @description: 添加 superu 用户到 wheel 组
    # @param {*}
    # @return {*}
    ###

    if `cat /etc/passwd | grep superu > /dev/null`;then
        id -Gn superu | grep wheel > /dev/null
        if [ $? != 0 ];then
            echo -e "${FG_GREEN}[Success]: Add superu to wheel group... ${FG_DEFAULT}" | tee -a ${LOGFILE}
            usermod -G wheel superu
        else
            echo -e "${FG_CYAN}[Info]: The user 'superu' is already in wheel group... ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    else
        echo -e "${FG_RED}[Error]: The user 'superu' is not exist!\n failed add to wheel group ${FG_DEFAULT}" | tee -a ${LOGFILE}
        return 1
    fi
}

function limit_su(){
    ###
    # @description: 禁止 wheel 组之外用户切换到 root
    # @param {*}
    # @return {*}
    ###

__output="
########################
# 限制非 wheel 组切换到 root
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    sufile="/etc/pam.d/su"
    if add2wheel;then
        egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*$" > /dev/null
        if [ $? == 0 ];then
            egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*group=wheel" > /dev/null
            if [ $? == 0 ];then
                echo -e "${FG_CYAN}[Info]: Already limit su functionality for non-wheel users... ${FG_DEFAULT}" | tee -a ${LOGFILE}
            else
                sed -i 's/^auth.*required.*pam_wheel.so.*$/& group=wheel/g' ${sufile}
            fi
        else
            echo 'auth		required	pam_wheel.so group=wheel' >> ${sufile}
        fi

    else
        echo -e "${FG_RED}[Error]: Su limitation setting failed! ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi
}

function remote_login(){
    ###
    # @description: 限制 SSH 远程登陆
    # @param {*}
    # @return {*}
    ###

__output="
########################
# 限制 Root 远程登陆
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    echo >> /etc/ssh/sshd_config
    grep -E '^Protocol' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "${FG_RED}[Error]: Failed to set Protocol to 2 ${FG_DEFAULT}" | tee -a ${LOGFILE}
        else
            echo -e "${FG_GREEN}[Success]: Set SSH Protocol to 2 ${FG_DEFAULT}" | tee -a ${LOGFILE}
         fi
    else
        echo 'Protocol 2' >> /etc/ssh/sshd_config
        echo -e "${FG_GREEN}[Success]: Set SSH Protocol to 2 ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi
    
    echo -e "${BYELLOW}Please make sure you have created at least one another account! ${BDEFAULT}" | tee -a ${LOGFILE}
    grep -E '^PermitRootLogin no$' /etc/ssh/sshd_config > /dev/null
    if [ $? == 1 ];then
            grep -E '(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)' /etc/ssh/sshd_config >/dev/null
            if [ $? == 0 ];then
                sed -i -r 's/(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)/PermitRootLogin no/g' /etc/ssh/sshd_config
                if [ $? != 0 ];then
                    echo -e "${FG_RED}[Error]: Failed to set PermitRootLogin to 'no' ${FG_DEFAULT}" | tee -a ${LOGFILE}
                else
                echo -e "${FG_GREEN}[Success]: Successfully disable root remote login. ${FG_DEFAULT}" | tee -a ${LOGFILE}
                RESTART_FLAG=0
                fi
            else
                echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
                echo -e "${FG_GREEN}[Success]: Successfully disable root remote login. ${FG_DEFAULT}" | tee -a ${LOGFILE}
                RESTART_FLAG=0
            fi
    else
        echo -e "${FG_CYAN}[Info]: Already disable root remote login. ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi

}

function set_history_tmout(){
    ###
    # @description: 配置历史操作记录以及超时登出
    # @param {*}
    # @return {*}
    ###

__output="
########################
# 配置命令历史记录及会话超时登出
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    # history size
    grep -E "^HISTSIZE=" /etc/profile >/dev/null
    if [ $? == 0 ];then
        sed -i "s/^HISTSIZE=.*$/HISTSIZE=${BASH_HISTORY_SIZE}/g" /etc/profile
    else
        echo 'HISTSIZE=${BASH_HISTORY_SIZE}' >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${FG_GREEN}[Success]: HISTSIZE has been set to ${BASH_HISTORY_SIZE} ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi

    # history format
    grep -E "^export HISTTIMEFORMAT=" /etc/profile > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^export HISTTIMEFORMAT=.*$/export HISTTIMEFORMAT="%F %T `whoami`"/g' /etc/profile
    else
        echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${FG_GREEN}[Success]: HISTTIMEFORMAT has been set to 'Number-Time-User-Command' ${FG_DEFAULT}" | tee -a ${LOGFILE}
    fi

    #TIME_OUT
    grep -E "^TMOUT=" /etc/profile	> /dev/null
    if [ $? == 0 ];then
        sed -i "s/^TMOUT=.*$/TMOUT=${BASH_TMOUT}/g" /etc/profile
    else
        echo "TMOUT=${BASH_TMOUT}" >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${FG_GREEN}[Success]: TMOUT has been set to ${BASH_TMOUT} ${FG_DEFAULT}" | tee -a ${LOGFILE}
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

__output="
########################
# 用户相关文件设置 immutable（+i)
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    for file in /etc/gshadow /etc/passwd /etc/group /etc/shadow
    do
        if [ -f ${file} ]; then
            lsattr ${file} | grep -E "^.{4}i" > /dev/null
            if [ $? != 0 ];then
                chattr +i ${file}
                if [ $? == 0 ];then
                    echo -e "${FG_GREEN}[Success]: Immutable ${file} ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            else
                echo -e "${FG_CYAN}[Info]: Already immutable ${file} ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        else
            echo -e "${FG_RED}[Error]: File '${file}' not exist ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    done
}

function limit_system_files() {
    ###
     # @description: 重要目录或文件权限设置
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 重要目录或文件权限设置
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}
    
    # limit rc script
    for file in /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rc.d/init.d
    do
        if [ -d ${file} ] || [ -h ${file} ]; then
            ret=`stat -c "%a" ${file}`
            if [ ${ret} -ne 750 ]; then
                chmod 750 ${file}
                if [ $? == 0 ]; then
                    echo -e "${FG_GREEN}[Success]: ${file} permissions changed to 750 ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            elif [ ${ret} -eq 750 ]; then
                echo -e "${FG_CYAN}[Info]: ${file} permissions already set to 750 ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        else
            echo -e "${FG_RED}[Error]: File '${file}' not exist ${FG_DEFAULT}" | tee -a ${LOGFILE}
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
                    echo -e "${FG_GREEN}[Success]: ${file} permissions changed to 600 ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            elif [ ${ret} -eq 600 ]; then
                echo -e "${FG_CYAN}[Info]: ${file} permissions already set to 600 ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        else
            echo -e "${FG_RED}[Error]: File '${file}' not exist ${FG_DEFAULT}" | tee -a ${LOGFILE}
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
                    echo -e "${FG_GREEN}[Success]: ${file} permissions changed to 644 ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            elif [ ${ret} -eq 644 ]; then
                echo -e "${FG_CYAN}[Info]: ${file} permissions already set to 644 ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        else
            echo -e "${FG_RED}[Error]: File '${file}' not exist ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    done
}

function umask_profile() {
    ###
     # @description: 用户 umask 设置
     # @param {*}
     # @return {*}
    ###

__output="
########################
# 用户 umask 设置
########################
"
    echo -e "${FG_CYAN}${__output} ${FG_DEFAULT} " | tee -a ${LOGFILE}

    for file in /etc/bashrc /etc/csh.cshrc /etc/profile /etc/csh.login
    do
        if [ -f ${file} ]; then
            grep -E 'umask 077$' /etc/profile > /dev/null
            if [ $? != 0 ]; then
                sed -i -r 's/umask .{3}$/umask 077/g' ${file}
                if [ $? == 0 ]; then
                    echo -e "${FG_GREEN}[Success]: 'umask' in ${file} set to 077 ${FG_DEFAULT}" | tee -a ${LOGFILE}
                fi
            else
                echo -e "${FG_CYAN}[Info]: 'umask' in ${file} already set to 077 ${FG_DEFAULT}" | tee -a ${LOGFILE}
            fi
        else
            echo -e "${FG_RED}[Error]: File '${file}' not exist ${FG_DEFAULT}" | tee -a ${LOGFILE}
        fi
    done
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
            echo `date '+%Y/%m/%d %T'` >> ${LOGFILE}
            backup
            get_os_type
            password
            limit_su
            remote_login
            set_history_tmout
            limit_system_files
            umask_profile
            immutable_user_conf_file
            restart_ssh
            ;;
        2)  
            echo `date '+%Y/%m/%d %T'` >> ${LOGFILE}
            restore
            ;;
        0)  break
            ;;
        *)  echo "Invalid entry."
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
main