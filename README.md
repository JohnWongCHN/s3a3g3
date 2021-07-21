# 等保 3.0 级基线配置脚本

目前仅支持 Redhat 6,7 系列发行版

## 使用说明

脚本执行会有日志输出，注意查看输出的日志信息有无异常，另外所有日志都会写入到同目录下 `s3a3g3.log` 文件中

日志输出有四种状态，分别是 `INFO`, `WARRN`, `ERROR`, `SUCCESS`
需要留意的是 `ERROR` 状态，`INFO` 以及 `WARRN` 状态影响不大，可以忽略

使用过程中要是遇到问题，及时反应给我(huangqw@xmeport.cn)

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

* 脚本不添加执行权限
  
```bash
[root@xxxx ~]# bash s3a3g3.sh -h
等保3级基线配置脚本 - by John Wong (john-wong@outlook.com)

s3a3g3 version: v0.2
Usage: s3a3g3.sh [-hrba]

Options:
  -h,--help           : this help
  -r,--recovery       : recover all the changes
  -b,--backup         : backup configure files
  -a,--apply          : apply settings

```

* 脚本添加执行权限

```bash
[root@xxxx ~]# chmod +x s3a3g3.sh
[root@xxxx ~]# ./s3a3g3.sh -h
等保3级基线配置脚本 - by John Wong (john-wong@outlook.com)

s3a3g3 version: v0.2
Usage: s3a3g3.sh [-hrba]

Options:
  -h,--help           : this help
  -r,--recovery       : recover all the changes
  -b,--backup         : backup configure files
  -a,--apply          : apply settings

```

### 参数说明

* `-h, --help` 查看脚本帮助

```bash
[root@xxxx ~]# chmod +x s3a3g3.sh
[root@xxxx ~]# ./s3a3g3.sh -h
等保3级基线配置脚本 - by John Wong (john-wong@outlook.com)

s3a3g3 version: v0.2
Usage: s3a3g3.sh [-hrba]

Options:
  -h,--help           : this help
  -r,--recovery       : recover all the changes
  -b,--backup         : backup configure files
  -a,--apply          : apply settings

```

* `-b,--backup` 备份配置文件

备份配置文件，会在当前目录生产 `s3a3g3-backup` 目录，当已经存在该目录时会提示覆盖该目录还是
修改原目录名，修改后的文件名类似于 `s3a3g3-backup-202107210905`

```bash
[root@xxxx ~]# bash s3a3g3.sh -b
```

* `-r,--recovery` 恢复原配置

恢复原配置将会把 `s3a3g3-backup` 目录中的备份配置文件覆盖原文件

```bash
[root@xxxx ~]# bash s3a3g3.sh -r
```

* `-a,--apply` 应用基线配置

应用所有基线配置

```bash
[root@xxxx ~]# bash s3a3g3.sh -a
```
