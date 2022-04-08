# 等保 3 级基线配置脚本

## 更新历史

- ⚙️ 2022-04-08, 重构代码，加入 RHEL 8 发行版支持，添加网络加固功能（防火墙 SSH 白名单，ICMP 白名单），添加执行权限检查（非 root/sudo 权限无法执行脚本）

目前仅支持 Redhat 6,7,8 系列发行版

## 使用说明

脚本执行会有日志输出，注意查看输出的日志信息有无异常，另外所有日志都会写入到同目录下 `s3a3g3.log` 文件中

日志输出有四种状态，分别是 `INFO`, `WARRN`, `ERROR`, `SUCCESS`
需要留意的是 `ERROR` 状态，`INFO` 以及 `WARRN` 状态影响不大，可以忽略

示例

```bash
[root@xxxx ~]# bash s3a3g3.sh -a
[2021/07/21 16:16:54] [INFO] [get_os_type] > Getting OS type...
[2021/07/21 16:16:54] [INFO] [get_os_type] > Current OS release: CentOS Linux 7 (Core)
[2021/07/21 16:16:54] [SUCCESS] [get_os_type] > Supported OS release: 7
[2021/07/21 16:16:54] [INFO] [backup] > Backup files ...
[2021/07/21 16:16:54] [WARRN] [backup] > Backup directory already exists...
Overwrite or move to new name ? [m|move (default), o|overwrite, c|cancel] > m
[2021/07/21 16:16:55] [INFO] [backup] > Backup files ...
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/pam.d/system-auth to s3a3g3-backup/system-auth.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/pam.d/system-auth-ac to s3a3g3-backup/system-auth-ac.bak
[2021/07/21 16:16:55] [WARRN] [backup] > /etc/pam.d/common-password does not exist
[2021/07/21 16:16:55] [WARRN] [backup] > ~/.ssh/authorized_keys does not exist
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/pam.d/sshd to s3a3g3-backup/sshd.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/sudoers to s3a3g3-backup/sudoers.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/ssh/sshd_config to s3a3g3-backup/sshd_config.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/profile to s3a3g3-backup/profile.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/bashrc to s3a3g3-backup/bashrc.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/csh.cshrc to s3a3g3-backup/csh.cshrc.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/csh.login to s3a3g3-backup/csh.login.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/pam.d/su to s3a3g3-backup/su.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/login.defs to s3a3g3-backup/login.defs.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/security/pwquality.conf to s3a3g3-backup/pwquality.conf.bak
[2021/07/21 16:16:55] [SUCCESS] [backup] > Copy /etc/sysctl.conf to s3a3g3-backup/sysctl.conf.bak
....
```

### 执行方式

- 脚本不添加执行权限
  
```bash
[root@xxxx ~]# bash s3a3g3.sh -h
s3a3g3.sh ver. 0.5.0
等保3级基线配置脚本

Usage: s3a3g3.sh [-h|--help]
       s3a3g3.sh [-r|--recovery] [-b|--backup] [-a|--apply] [-s|--secure-network]

  Options:
  -h, --help                  Display this help message and exit.
  -r, --recovery              recover all the changes
  -b, --backup                backup configure files
  -a, --apply                 apply settings
  -s, --secure-network        secure network configuration (firewalld, not support iptables)

  NOTE: You must be the superuser to run this script.

```

- 脚本添加执行权限

```bash
[root@xxxx ~]# chmod +x s3a3g3.sh
[root@xxxx ~]# ./s3a3g3.sh -h
s3a3g3.sh ver. 0.5.0
等保3级基线配置脚本

Usage: s3a3g3.sh [-h|--help]
       s3a3g3.sh [-r|--recovery] [-b|--backup] [-a|--apply] [-s|--secure-network]

  Options:
  -h, --help                  Display this help message and exit.
  -r, --recovery              recover all the changes
  -b, --backup                backup configure files
  -a, --apply                 apply settings
  -s, --secure-network        secure network configuration (firewalld, not support iptables)

  NOTE: You must be the superuser to run this script.

```

### 参数说明

- `-h, --help` 查看脚本帮助

```bash
[root@xxxx ~]# chmod +x s3a3g3.sh
[root@xxxx ~]# ./s3a3g3.sh -h
s3a3g3.sh ver. 0.5.0
等保3级基线配置脚本

Usage: s3a3g3.sh [-h|--help]
       s3a3g3.sh [-r|--recovery] [-b|--backup] [-a|--apply] [-s|--secure-network]

  Options:
  -h, --help                  Display this help message and exit.
  -r, --recovery              recover all the changes
  -b, --backup                backup configure files
  -a, --apply                 apply settings
  -s, --secure-network        secure network configuration (firewalld, not support iptables)

  NOTE: You must be the superuser to run this script.

```

- `-b,--backup` 备份配置文件

备份配置文件，会在当前目录生产 `s3a3g3-backup` 目录，当已经存在该目录时会提示覆盖该目录还是
修改原目录名，修改后的文件名类似于 `s3a3g3-backup-202107210905`

```bash
[root@xxxx ~]# bash s3a3g3.sh -b
```

- `-r,--recovery` 恢复原配置

恢复原配置将会把 `s3a3g3-backup` 目录中的备份配置文件覆盖原文件

```bash
[root@xxxx ~]# bash s3a3g3.sh -r
```

- `-a,--apply` 应用基线配置

应用所有基线配置

```bash
[root@xxxx ~]# bash s3a3g3.sh -a
```

- `-s,--secure-network` 防火墙加固

网络安全，防火墙架构，设置 SSH 白名单，ICMP Ping 白名单

```bash
[root@xxxx ~]# bash s3a3g3.sh -s
```
