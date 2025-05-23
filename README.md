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
- Add patch version(latest vulnerable version +1)
- Add affected functions
- Add .diff for each `valid` CVE manually
- > test CVEs in `first_patch.json`

## 实验流程
1. 预先准备
    - 目标CVE，在first_batch.json中。一个CWE对应10个CVE。 
    - Diff文件：./Diff/程序名/ 会有diff文件，部分工具(PS3)需要diff文件作为输入
    - 漏洞补丁修改的函数名，这个目前json文件里面还没有，需要提取
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
### 备注
- REACT使用的不是reference binary，是LLVM的.bc文件，编译器使用clang，编译时emit llvm即可。
- 目前的diff文件还不完善，我会继续完善
- 将漏洞补丁修改函数名提取出，放入_filtered.json这个工作我来做。
- `先选择first_batch.json中前五个类别，每个类别前五个CVE，共25个CVE来进行测试1`。每个CVE需要编译出2个binary作为reference，6个binary作为target。实验评价标准沿用原文(P,R,F1)。