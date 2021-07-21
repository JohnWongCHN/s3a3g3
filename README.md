# 等保 3.0 级基线配置脚本

目前仅支持 Redhat 6,7 系列发行版

## 使用说明

脚本执行会有日志输出，注意查看输出的日志信息有无异常，另外所有日志都会写入到同目录下 `s3a3g3.log` 文件中

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
