# BITWebHelper

### 介绍

跨平台BIT校园网登录器，基于.net 6



### 安装

命令行直接运行即可



### 使用说明

本程序包含三个子指令：登录、注销、检查登录状态

每一指令的执行结果在以文本形式输出的同时，会通过返回值指明成功与否，0为成功，1为失败



#### 登录

BITWebHelper login \<access_id\> \<username\> \<password\>

登录指定账户

access_id：一般为1或8，请查询本地网络登陆界面网址中的ac_id

username：学号

password：密码



#### 注销

BITWebHelper logout \<access_id\> \<username\>

注销指定账户

access_id：一般为1或8，请查询本地网络登陆界面网址中的ac_id

username：学号



#### 检查登录状态

BITWebHelper check

检查当前是否已经登录，除文本输出之外，将通过返回值指明登录与否，0为已登录，1为未登录





~~如果你的平台是Windows，且不包含.Net 6环境，请参见基于.net framework构建的传统版本（已废弃）[BITWebHelper-NF](https://gitee.com/ckblau/bitwebhelper-nf)~~

