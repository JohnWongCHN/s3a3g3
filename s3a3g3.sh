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
###

###
 # @Author: John Wong
 # @Date: 2021-06-01 11:34:15
 # @LastEditors: John Wong
 # @LastEditTime: 2021-06-01 11:40:28
 # @FilePath: /Shell_Script/Protective_Script/s3a3g3.sh
 # @Desc: 基于等保3.0，在集团环境下的针对性保护配置
 # @Version: 0.1
### 


### Global Variables ###
restart_flag=1
ostype='unknow'
# 操作日志
logfile=s3a3g3.log
bash_history_size=10000
bash_tmout=600
# 备份目录
backupdirname=s3a3g3_backup
# 原备份文件
declare -a origin_filepaths=(
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
DEFAULT='\e[39m'
NOCOLOR='\e[0m'
RED='\e[0;31m'
GREEN='\e[0;32m'
ORANGE='\e[0;33m'
BLUE='\e[0;34m'
PURPLE='\e[0;35m'
CYAN='\e[0;36m'
LIGHTGRAY='\e[0;37m'
DARKGRAY='\e[1;30m'
LIGHTRED='\e[1;31m'
LIGHTGREEN='\e[1;32m'
YELLOW='\e[1;33m'
LIGHTBLUE='\e[1;34m'
LIGHTPURPLE='\e[1;35m'
LIGHTCYAN='\e[1;36m'
WHITE='\e[1;37m'
# Background Colors
BDEFAULT='\e[49m'
BRED='\e[0;41m'
BGREEN='\e[0;42m'
BORANGE='\e[0;43m'
BBLUE='\e[0;44m'
BPURPLE='\e[0;45m'
BCYAN='\e[0;46m'
BLIGHTGRAY='\e[0;47m'
BDARKGRAY='\e[1;40m'
BLIGHTRED='\e[1;41m'
BLIGHTGREEN='\e[1;42m'
BYELLOW='\e[1;43m'
BLIGHTBLUE='\e[1;44m'
BLIGHTPURPLE='\e[1;45m'
BLIGHTCYAN='\e[1;46m'
BWHITE='\e[1;47m'


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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    if [ -f /etc/redhat-release ];then
        grep -i 'CentOS' /etc/redhat-release > /dev/null
        if [ $? == 0 ];then
            ostype='CentOS'
        fi
        grep -i 'Redhat' /etc/redhat-release > /dev/null
        if [ $? == 0 ];then
            ostype='Redhat'
        fi
    fi

    if [ -f /etc/centos-release ];then
        grep -i 'Centos' /etc/centos-release > /dev/null
        if [ $? == 0 ];then
            ostype='Centos'
        fi
    fi
    echo -e "${LIGHTBLUE}[Info]: OSTYPE is ${ostype} ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    echo -e "${LIGHTBLUE}[Info]: Please restart SSH service manully \n ('service sshd restart' or 'systemctl restart sshd'). ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    if [ ! -d ${backupdirname} ]; then
        mkdir ${backupdirname}
        for filepath in "${origin_filepaths[@]}"
        do
            if [ -f ${filepath} ]; then
                filename=`echo ${filepath} | awk -F '/' '{print $NF}'`
                cp -a ${filepath} ${backupdirname}/${filename}.bak
                if [ $? == 0 ]; then
                    echo -e "${GREEN}[Success]: Backup ${filepath} to ${backupdirname}/${filename}.bak ${DEFAULT}" | tee -a ${logfile}
                else
                    echo -e "${RED}[Error]: Failed to backup ${filepath} to ${backupdirname}/${filename}.bak ${DEFAULT}" | tee -a ${logfile}
                fi
            fi
        done
    else
        echo -e "${LIGHTBLUE}[Info]: Backup file already exist, to avoid overwriting these\n  files, backup will not perform again ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    for filepath in "${origin_filepaths[@]}"
    do
        backup_filepath=${backupdirname}/`echo ${filepath} | awk -F '/' '{print $NF}'`.bak
        if [ -f ${backup_filepath} ]; then
            # filename=`echo ${filepath} | awk -F '/' '{print $NF}'`
            cp -a ${backup_filepath} ${filepath}
            if [ $? == 0 ]; then
                echo -e "${GREEN}[Success]: Restore ${backup_filepath} to ${filepath} ${DEFAULT}" | tee -a ${logfile}
            else
                echo -e "${RED}[Error]: Failed to restore ${backup_filepath} to ${filepath} ${DEFAULT}" | tee -a ${logfile}
            fi
        fi
    done

    source /etc/profile
    restart_flag=0
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    if [ -f /etc/pam.d/system-auth ];then
        config="/etc/pam.d/system-auth"
    elif [ -f /etc/pam.d/common-password ];then
        config="/etc/pam.d/common-password"
    else
        echo -e "${RED}[Error]: Doesn't support this OS. ${DEFAULT}" | tee -a ${logfile}
        return 1
    fi

    grep -E "^password.*requisite.*pam_cracklib.so" $config  > /dev/null
    if [ $? == 0 ];then
        sed -i "s/^password.*requisite.*pam_cracklib\.so.*$/password    requisite       pam_cracklib.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" $config
	    echo -e "${LIGHTBLUE}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${DEFAULT}" | tee -a ${logfile}
    else
        grep -E "pam_pwquality\.so" $config > /dev/null
        if [ $? == 0 ];then
            sed -i "s/password.*requisite.*pam_pwquality\.so.*$/password     requisite       pam_pwquality.so retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5/g" $config
	        echo -e "${LIGHTBLUE}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${DEFAULT}" | tee -a ${logfile}
        else
            echo 'password      requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5' >> $config
	        echo -e "${LIGHTBLUE}参数: retry=3 difok=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5 ${DEFAULT}" | tee -a ${logfile}
        fi
    fi

    if [ $? == 0 ];then
        echo -e "${GREEN}[Success]: Password complexity set successed ${DEFAULT}" | tee -a ${logfile}
    else
        echo -e "${RED}[Error]: Password complexity set failed ${DEFAULT}" | tee -a ${logfile}
	    exit 1
    fi

    grep -E '^PASS_MAX_DAYS.*90' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g" /etc/login.defs
        if [ $? == 0 ] ;then
            echo -e "${GREEN}[Success]: /etc/login.defs set to 'PASS_MAX_DAYS 90' ${DEFAULT}" | tee -a ${logfile}
        else
            echo -e "${RED}[Error]: /etc/login.defs set to 'PASS_MAX_DAYS 90' failed ${DEFAULT}" | tee -a ${logfile}
        fi
    else
        echo -e "${LIGHTBLUE}[Info]: /etc/login.defs already set 'PASS_MAX_DAYS 90' ${DEFAULT}" | tee -a ${logfile}
    fi

    grep -E '^PASS_MIN_DAYS.*6' /etc/login.defs > /dev/null
    if [ $? != 0 ];then
        sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 6/g" /etc/login.defs
        if [ $? == 0 ] ;then
            echo -e "${GREEN}[Success]: /etc/login.defs set to 'PASS_MIN_DAYS 6' ${DEFAULT}" | tee -a ${logfile}
        else
            echo -e "${RED}[Error]: /etc/login.defs set to 'PASS_MIN_DAYS 6' failed ${DEFAULT}" | tee -a ${logfile}
        fi
    else
        echo -e "${LIGHTBLUE}[Info]: /etc/login.defs already set 'PASS_MIN_DAYS 6' ${DEFAULT}" | tee -a ${logfile}
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
            echo -e "${GREEN}[Success]: Add superu to wheel group... ${DEFAULT}" | tee -a ${logfile}
            usermod -G wheel superu
        else
            echo -e "${LIGHTBLUE}[Info]: The user 'superu' is already in wheel group... ${DEFAULT}" | tee -a ${logfile}
        fi
    else
        echo -e "${RED}[Error]: The user 'superu' is not exist!\n failed add to wheel group ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    sufile="/etc/pam.d/su"
    if add2wheel;then
        egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*$" > /dev/null
        if [ $? == 0 ];then
            egrep -v "^#.*" ${sufile} | egrep "^auth.*required.*pam_wheel.so.*group=wheel" > /dev/null
            if [ $? == 0 ];then
                echo -e "${LIGHTBLUE}[Info]: Already limit su functionality for non-wheel users... ${DEFAULT}" | tee -a ${logfile}
            else
                sed -i 's/^auth.*required.*pam_wheel.so.*$/& group=wheel/g' ${sufile}
            fi
        else
            echo 'auth		required	pam_wheel.so group=wheel' >> ${sufile}
        fi

    else
        echo -e "${RED}[Error]: Su limitation setting failed! ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    echo >> /etc/ssh/sshd_config
    grep -E '^Protocol' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "${RED}[Error]: Failed to set Protocol to 2 ${DEFAULT}" | tee -a ${logfile}
        else
            echo -e "${GREEN}[Success]: Set SSH Protocol to 2 ${DEFAULT}" | tee -a ${logfile}
         fi
    else
        echo 'Protocol 2' >> /etc/ssh/sshd_config
        echo -e "${GREEN}[Success]: Set SSH Protocol to 2 ${DEFAULT}" | tee -a ${logfile}
    fi
    
    echo -e "${BYELLOW}Please make sure you have created at least one another account! ${BDEFAULT}" | tee -a ${logfile}
    grep -E '^PermitRootLogin no$' /etc/ssh/sshd_config > /dev/null
    if [ $? == 1 ];then
            grep -E '(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)' /etc/ssh/sshd_config >/dev/null
            if [ $? == 0 ];then
                sed -i -r 's/(.*PermitRootLogin yes$)|(.*PermitRootLogin prohibit\-password$)/PermitRootLogin no/g' /etc/ssh/sshd_config
                if [ $? != 0 ];then
                    echo -e "${RED}[Error]: Failed to set PermitRootLogin to 'no' ${DEFAULT}" | tee -a ${logfile}
                else
                echo -e "${GREEN}[Success]: Successfully disable root remote login. ${DEFAULT}" | tee -a ${logfile}
                restart_flag=0
                fi
            else
                echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
                echo -e "${GREEN}[Success]: Successfully disable root remote login. ${DEFAULT}" | tee -a ${logfile}
                restart_flag=0
            fi
    else
        echo -e "${LIGHTBLUE}[Info]: Already disable root remote login. ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    # history size
    grep -E "^HISTSIZE=" /etc/profile >/dev/null
    if [ $? == 0 ];then
        sed -i "s/^HISTSIZE=.*$/HISTSIZE=${bash_history_size}/g" /etc/profile
    else
        echo 'HISTSIZE=${bash_history_size}' >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${GREEN}[Success]: HISTSIZE has been set to ${bash_history_size} ${DEFAULT}" | tee -a ${logfile}
    fi

    # history format
    grep -E "^export HISTTIMEFORMAT=" /etc/profile > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^export HISTTIMEFORMAT=.*$/export HISTTIMEFORMAT="%F %T `whoami`"/g' /etc/profile
    else
        echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${GREEN}[Success]: HISTTIMEFORMAT has been set to 'Number-Time-User-Command' ${DEFAULT}" | tee -a ${logfile}
    fi

    #TIME_OUT
    grep -E "^TMOUT=" /etc/profile	> /dev/null
    if [ $? == 0 ];then
        sed -i "s/^TMOUT=.*$/TMOUT=${bash_tmout}/g" /etc/profile
    else
        echo "TMOUT=${bash_tmout}" >> /etc/profile
    fi
    if [ $? == 0 ];then
        echo -e "${GREEN}[Success]: TMOUT has been set to ${bash_tmout} ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    for file in /etc/gshadow /etc/passwd /etc/group /etc/shadow
    do
        if [ -f ${file} ]; then
            lsattr ${file} | grep -E "^.{4}i" > /dev/null
            if [ $? != 0 ];then
                chattr +i ${file}
                if [ $? == 0 ];then
                    echo -e "${GREEN}[Success]: Immutable ${file} ${DEFAULT}" | tee -a ${logfile}
                fi
            else
                echo -e "${LIGHTBLUE}[Info]: Already immutable ${file} ${DEFAULT}" | tee -a ${logfile}
            fi
        else
            echo -e "${RED}[Error]: File '${file}' not exist ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}
    
    # limit rc script
    for file in /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rc.d/init.d
    do
        if [ -d ${file} ] || [ -h ${file} ]; then
            ret=`stat -c "%a" ${file}`
            if [ ${ret} -ne 750 ]; then
                chmod 750 ${file}
                if [ $? == 0 ]; then
                    echo -e "${GREEN}[Success]: ${file} permissions changed to 750 ${DEFAULT}" | tee -a ${logfile}
                fi
            elif [ ${ret} -eq 750 ]; then
                echo -e "${LIGHTBLUE}[Info]: ${file} permissions already set to 750 ${DEFAULT}" | tee -a ${logfile}
            fi
        else
            echo -e "${RED}[Error]: File '${file}' not exist ${DEFAULT}" | tee -a ${logfile}
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
                    echo -e "${GREEN}[Success]: ${file} permissions changed to 600 ${DEFAULT}" | tee -a ${logfile}
                fi
            elif [ ${ret} -eq 600 ]; then
                echo -e "${LIGHTBLUE}[Info]: ${file} permissions already set to 600 ${DEFAULT}" | tee -a ${logfile}
            fi
        else
            echo -e "${RED}[Error]: File '${file}' not exist ${DEFAULT}" | tee -a ${logfile}
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
                    echo -e "${GREEN}[Success]: ${file} permissions changed to 644 ${DEFAULT}" | tee -a ${logfile}
                fi
            elif [ ${ret} -eq 644 ]; then
                echo -e "${LIGHTBLUE}[Info]: ${file} permissions already set to 644 ${DEFAULT}" | tee -a ${logfile}
            fi
        else
            echo -e "${RED}[Error]: File '${file}' not exist ${DEFAULT}" | tee -a ${logfile}
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
    echo -e "${CYAN}${__output} ${DEFAULT} " | tee -a ${logfile}

    for file in /etc/bashrc /etc/csh.cshrc /etc/profile /etc/csh.login
    do
        if [ -f ${file} ]; then
            grep -E 'umask 077$' /etc/profile > /dev/null
            if [ $? != 0 ]; then
                sed -i -r 's/umask .{3}$/umask 077/g' ${file}
                if [ $? == 0 ]; then
                    echo -e "${GREEN}[Success]: 'umask' in ${file} set to 077 ${DEFAULT}" | tee -a ${logfile}
                fi
            else
                echo -e "${LIGHTBLUE}[Info]: 'umask' in ${file} already set to 077 ${DEFAULT}" | tee -a ${logfile}
            fi
        else
            echo -e "${RED}[Error]: File '${file}' not exist ${DEFAULT}" | tee -a ${logfile}
        fi
    done
}

function main(){
    ###
     # @description: main function
     # @param {*}
     # @return {*}
    ###
_menu="
##########################
#  Menu                  #
#   1: ALL protective    #
#   2: Restore files     #
#   3: Exit              #
##########################
"
    echo  -e "${GREEN}${_menu} ${DEFAULT}"
    read -p "Please choice[1-3]: "
    case $REPLY in
        1)
            echo `date '+%Y/%m/%d %T'` >> ${logfile}
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
            echo `date '+%Y/%m/%d %T'` >> ${logfile}
            restore
        ;;
        3)
            exit 0
        ;;
        *)
            echo -e ""
            echo -e "请输入 1-3."
            echo -e ""
            main
        ;;
    esac
}


######################## 执行备份 ############################
main