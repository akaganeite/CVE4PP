## projects
- curl
- openssl
- tcpdump
- sqlite
- ffmpeg


## structure
- cveinfo: parsed cve information
- rawdata: cve info before any process
- releases: releae history of projects
- Diff: .diff for each CVE

## Todos
- > test CVEs in `first_patch.json`
- compile `openssl` binaries


## 实验流程
1. 预先准备
    - 目标CVE，在first_batch.json中。一个CWE对应10个CVE。 
    - Diff文件：./Diff/程序名/ 会有diff文件，部分工具(PS3)需要diff文件作为输入
    - 漏洞补丁修改的函数名，具体信息查看`diff.md`
2. 下载源码
    - git clone 远程仓库，所有的二进制文件构建都从源码编译，先不直接下载发行版安装包
3. 构建reference binary。
    - reference binary是签名生成的依据，diff文件名第三个字段是commit的hash value前6位
    - 用上述字段可以checkout到修复漏洞那个commit，使用默认优化级别编译(记得开完整debug info输出)。编译结果是patch 二进制
    - checkout到漏洞修复commit之前的那个commit，再编译。编译结果是vuln 二进制
    - 上述的patch/vuln 二进制将作为reference在签名生成阶段作为输入
4. 构建target binary。
    - target binary在测试时使用。
    - 测试1: `程序名_filtered.json`文件中`last_vuln_version`代表最后一个受该CVE影响的(vulnerable)的发行版本。选取`last_vuln_version`及其之前的两个发行版本，`last_vuln_version`之后的三个发行版本。共6个版本，三个vulnerable，三个patched，以默认编译选项compile，并测试。
> 2 3 4 部分在如下链接中有编译好的版本。如果需要自己编译的话参考Diff/{project}/compile.sh的bash脚本。除binutils外的脚本都会自动编译所需的target和reference二进制
> compiled binaries:https://drive.google.com/file/d/19heaZ2yUiJLUsM02Umv8UM8XtFPliHzg/view?usp=drive_link
### 备注
- REACT使用的不是reference binary，是LLVM的.bc文件，编译器使用clang，编译时emit llvm即可。

## testset
> 目前只完成了binutils,openssl,curl
- chosen.txt 初始选择的CVE
- compile*.sh 用于编译reference target二进制
- *.log 编译时的log
- valid 合格的CVE(用于签名生成与检测)
- versions 全部的release版本
- testset.json 为每个cve选择的testset的版本
- ground_truth.json 每个CVE的全部vuln patch版本，为理想数据集构建准备
- gen_target.py 构建测试集文件
- target_version.py 构建testset&ground_truth.json


## Openssl
- 选择最近的100个CVE，n个Diff文件
- 有80个Diff文件可以找到修改的函数
- 56个Diff文件可以编译出reference二进制
    - 无法checkout 到 patch/vuln commit
        - CVE-2020-1971_2154ab83e14e
        - CVE-2021-23839_30919ab80a47
        - CVE-2023-5678_34efaef6c103
    - 编译失败(-d;-d shared;-d shared no-apps均失败)
        - CVE-2016-2178_399944622df7
        - CVE-2016-2179
        - CVE-2016-2180
        - CVE-2016-2181
        - CVE-2016-2182
        - CVE-2016-6302
        - CVE-2016-6303
        - CVE-2016-6305
        - CVE-2016-6307
        - CVE-2016-6308
        - CVE-2016-6309
        - CVE-2016-7056
        - CVE-2016-8610
        - CVE-2017-3730
        - CVE-2017-3731
        - CVE-2017-3733
        - CVE-2017-3735
        - CVE-2018-0734
        - CVE-2022-0778
    - 找不到function symbol
        - CVE-2019-1549 (test)
        - CVE-2021-3450 (test)
        - CVE-2021-3711 (test)
        - CVE-2021-3711 (test)
        - CVE-2021-4160 (test)
        - CVE-2022-1434
        - CVE-2022-4203
        - CVE-2023-0216
        - CVE-2023-0217

## binutils
- 选择80个CVE
- 以下8个CVE无法找到diff文件：
    - CVE-2021-32256
    - CVE-2021-3530
    - CVE-2018-12934
    - CVE-2018-12699
    - CVE-2018-12698
    - CVE-2018-12697
    - CVE-2018-12641
    - CVE-2017-9044
- 以下7CVE的diff文件无效
    - CVE-2017-16826
    - CVE-2017-16827
    - CVE-2017-16832
    - CVE-2017-17123
    - CVE-2018-19931
    - CVE-2018-7642
    - CVE-2019-12972
- 以下8个CVE编译出的reference找不到目标函数
    - CVE-2017-17121
    - CVE-2017-17125
    - CVE-2018-18309
    - CVE-2020-16592
    - CVE-2020-21490
    - CVE-2023-25584
    - CVE-2023-25585
    - CVE-2023-25588

## curl
- 选择了70个CVE
- 以下17个CVE无法找到diff文件：
    - CVE-2020-19909
    - CVE-2019-5443
    - CVE-2016-8620
    - CVE-2016-8616
    - CVE-2016-8615
    - CVE-2016-4802
    - CVE-2016-0755
    - CVE-2016-0754
    - CVE-2015-3236
    - CVE-2015-3148
    - CVE-2015-3143
    - CVE-2014-0139
    - CVE-2014-0138
    - CVE-2013-4545
    - CVE-2013-2174
    - CVE-2011-3389
    - CVE-2005-0490
- 以下1个CVE的diff文件无效
    - CVE-2003-1605
- 以下8个CVE编译出的reference找不到目标函数
    - CVE-2014-2522
    - CVE-2015-3237
    - CVE-2016-8619
    - CVE-2016-9952
    - CVE-2016-9953
    - CVE-2018-1000121
    - CVE-2019-5481
    - CVE-2021-22897
- 以下6个CVE编译reference失败
    - CVE-2014-3613
    - CVE-2014-3620
    - CVE-2015-3144
    - CVE-2015-3145
    - CVE-2015-3153
    - CVE-2016-3739

## sqlite
-  选择了49个CVE
- 一下n个CVE找不到Diff文件
    - CVE-2020-13871
    - CVE-2022-35737
    - CVE-2021-45346
    - CVE-2021-20227
    - CVE-2020-13871
    - CVE-2020-13435
    - CVE-2019-16168
    - CVE-2019-5018
    - CVE-2018-20506
    - CVE-2018-20505
    - CVE-2018-8740
    - CVE-2017-15286
    - CVE-2017-13685
    - CVE-2015-3414
    - CVE-2013-7443
- 以下1个CVE的Diff文件无效：
    - CVE-2015-3415
- 以下 个CVE编译出的reference找不到目标函数
    - CVE-2015-3416
    - CVE-2017-10989
    - CVE-2019-19603
    - CVE-2019-9936
    - CVE-2019-9937
    - CVE-2020-13631
    - CVE-2020-9327

##  libxml2
- 选择了57个CVE
- 找不到Diff文件
    - CVE-2003-1564
    - CVE-2010-4008
    - CVE-2013-2877
    - CVE-2016-9318
    - CVE-2019-20388
    - CVE-2023-39615
- Diff file无效
    - CVE-2023-29469
    - CVE-2020-24977
    - CVE-2017-7376
    - CVE-2016-4447
