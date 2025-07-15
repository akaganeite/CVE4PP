# DATASET FOR PATCH PRESENCE

## projects

- curl
- openssl
- libxml2
- sqlite
- ffmpeg
- binutils

## Works

- React
- PS3
- Robin
- BinXray

## structure

- project2cve.py: dump cve files in `rawdata/` 
  - source:`https://github.com/cve-search/cve-search.git`

- cveinfo: parsed cve information
- rawdata: cve info before any process
- releases: releae history of projects
- Diff: .diff for each CVE
- testset: data used to test related works for patch presence
- results: evaluation results for related works

### Diff

- diff_files/ : contains all diff files for a project
- details.py: parse .diff files in {project}/diff_files. Generate `details`
- convert_format.py: generate `details_llvm` for testing React

### testset

- gen_target.py 构建测试集文件
- target_version.py 构建testset&ground_truth.json
- valid2json.py: generate `CVE_info` and `test` jsonl files for React
- versions.py: dump `versions` file
- cve_compilation_issues.json: CVEs failed to generate reference binaries
- update_valid 
{project}/
- chosen.txt 初始选择的CVE
- compile*.sh 用于编译reference target 二进制or .bc
- logs/ log for compiling
- valid 合格的CVE(用于签名生成与检测)
- versions 全部的release版本
- testset.json 为每个cve选择的testset的版本
- ground_truth.json 每个CVE的全部vuln patch版本，为理想数据集构建准备

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

# Status of each project's CVEs

## Openssl

- 选择最近的100个CVE
- 有80个Diff文件可以找到修改的函数
- 56个Diff文件可以编译出reference二进制
  - 无法checkout 到 patch/vuln commit
    - CVE-2020-1971_2154ab83e14e
    - CVE-2021-23839_30919ab80a47
  - 编译reference失败
    - CVE-2016-2178
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
  - 编译出的reference找不到目标函数
    - CVE-2019-1547
    - CVE-2019-1549
    - CVE-2021-3450
    - CVE-2021-3711
    - CVE-2021-4160
    - CVE-2022-1434
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
- 编译出的reference找不到目标函数
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
- 编译出的reference找不到目标函数
  - CVE-2014-2522
  - CVE-2015-3237
  - CVE-2016-8619
  - CVE-2016-9952
  - CVE-2016-9953
  - CVE-2018-1000121
  - CVE-2019-5481
  - CVE-2021-22897
- 编译reference失败
  - CVE-2014-3613
  - CVE-2014-3620
  - CVE-2015-3144
  - CVE-2015-3145
  - CVE-2015-3153
  - CVE-2016-3739

## sqlite

- 选择了49个CVE
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
- 编译出的reference找不到目标函数
  - CVE-2015-3416
  - CVE-2017-10989
  - CVE-2019-19603
  - CVE-2019-9936
  - CVE-2019-9937
  - CVE-2020-13631
  - CVE-2020-9327

## libxml2

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
- 编译reference失败
  - CVE-2008-3281
  - CVE-2009-2414
  - CVE-2009-2416
  - CVE-2011-1944
  - CVE-2012-0841
- 编译出的reference找不到目标函数
  - CVE-2023-45322
  - CVE-2018-14567
  - CVE-2017-18258
  - CVE-2016-4448
  - CVE-2016-1839
- 无法编译target version
  - CVE-2008-3281
  - CVE-2009-2414
  - CVE-2009-2416

## ffmpeg

> 数据来源：https://ffmpeg.org/security.html

- 选择2020及之后的CVE，如果CVE影响多个发行版，任选其一
- diff文件无效：
  - CVE-2020-20448
  - CVE-2020-20892
  - CVE-2020-21041
  - CVE-2020-22040
  - CVE-2021-3566
  - CVE-2020-22028
- 编译出的reference找不到目标函数
  - CVE-2020-12284
  - CVE-2020-20450
  - CVE-2020-20451
  - CVE-2020-21688
  - CVE-2020-22016
  - CVE-2020-22025
  - CVE-2020-22032
  - CVE-2021-30123
  - CVE-2022-2566
  - CVE-2022-3341
  - CVE-2022-3964
  - CVE-2022-3965
  - CVE-2022-48434
  - CVE-2023-47344
  - CVE-2023-49502
  - CVE-2024-28661
  - CVE-2024-31582
  - CVE-2024-36617
  - CVE-2025-1816
- 编译出的二进制找到了多个同名的函数符号，无法检测
  - CVE-2020-22022
  - CVE-2020-22023
  - CVE-2020-22048
  - CVE-2020-22020
  - CVE-2020-22026
  - CVE-2020-22034
  - CVE-2023-50007
  - CVE-2020-22027
  - CVE-2020-22030
  - CVE-2020-22031
  - CVE-2020-22035
  - CVE-2020-20891
  - CVE-2020-22036
  - CVE-2020-35965
  - CVE-2020-23906
  - CVE-2023-50008
  - CVE-2025-0518
  - CVE-2025-22919
- 编译reference失败
  - CVE-2025-25471
  - CVE-2021-33815
  - CVE-2021-38114
  - CVE-2021-38171
- 找不到 target version
  - CVE-2023-47342
  - CVE-2023-47343
  - CVE-2023-47344
  - CVE-2023-49501
  - CVE-2023-49502
  - CVE-2024-28661
  - CVE-2024-31578
  - CVE-2024-31582
  - CVE-2024-36617
  - CVE-2024-7055
  - CVE-2025-1373
  - CVE-2025-1816
  - CVE-2025-22920

# Adjustment in target versions
## openssl
- failed to compile
  - OpenSSL_0_9_8zg
  - OpenSSL_1_1_0
  - OpenSSL_1_1_0a
  - OpenSSL_1_1_0-pre5
  - OpenSSL_1_1_0-pre6
  - OpenSSL_1_1_0b
  - OpenSSL_1_0_0t
  - openssl-3.0.0-alpha1
## curl
- failed to compile
  - 7.27.0
  - 7.28.0
  - 7.28.1
## ffmpeg
- fail to compile
  - 3.2.16
## sqlite
- fail to compile
  - 3.14


# Error in testset
## binutils
- false negative
  - 2.29.1

# Case Study Candidates
- CVE-2022-42916 create_conn
  - patch为pure deletion，后续添加代码和deletion部分有些类似
- CVE-2022-40304 xmlFreeEntity
- CVE-2019-19244 sqlite3Select
  - 使用`#ifndef`,`#idefine`的条件编译
- CVE-2019-19880 exprListAppendList
  -  v3.32.0有func upgrade 更改了代码看起来的样子，
- CVE-2021-36690
  -  挺有意思的，新增变量和对新增变量的操作
- CVE-2020-16590
  - 只更改了赋值语句的变量名
# both func not found in diff error
## curl
  - Curl_idn_strerror
  - idna_init
  - tld_check_name

# Robin succeed

## Overview
### func
project:has_sig/total | succeed/target
- binutils:18/80 | 49/363=13.50%
- Curl:2/58  | 7/351=1.99%
- ffmpeg:0/59 | 0/381=0%
- libxml2:22/89 | 106/558=19.00%
- openssl:14/87 ｜ 23/548=4.20%
- sqlite:11/44 ｜ 49/342=14.33%
### cve

## Details

```
CVE-2013-0338+xmlParserEntityCheck
CVE-2013-1944+tailmatch
CVE-2013-1969+htmlParseChunk
CVE-2014-0015+ConnectionExists
CVE-2014-8275+ASN1_verify
CVE-2014-8275+DSA_verify
CVE-2014-8275+ECDSA_verify
CVE-2015-1792+CMS_verify
CVE-2015-7498+xmlParseXMLDecl
CVE-2015-7498+xmlSwitchEncoding
CVE-2015-7500+xmlParseStartTag2
CVE-2015-7941+xmlParseConditionalSections
CVE-2015-8241+xmlParseMarkupDecl
CVE-2016-1762+xmlParseInternalSubset
CVE-2016-1836+xmlParseNCNameComplex
CVE-2016-1837+htmlParseSystemLiteral
CVE-2016-4658+xmlXPtrNewRangeNodeObject
CVE-2016-6153+unixGetTempname
CVE-2017-13710+setup_group
CVE-2017-14129+read_section
CVE-2017-14933+read_formatted_entries
CVE-2017-15020+parse_die
CVE-2017-15020+parse_line_table
CVE-2017-15024+find_abstract_instance_name
CVE-2017-15024+scan_unit_for_symbols
CVE-2017-15938+find_abstract_instance_name
CVE-2017-15939+decode_line_info
CVE-2017-15996+process_archive_index_and_symbols
CVE-2017-16831+_bfd_coff_get_external_symbols
CVE-2017-16831+coff_get_normalized_symtab
CVE-2017-5130+xmlMallocLoc
CVE-2017-5130+xmlMemStrdupLoc
CVE-2018-20346+fts3ScanInteriorNode
CVE-2018-20346+fts3SegReaderNext
CVE-2018-20671+load_specific_debug_section
CVE-2019-19645+renameTableFunc
CVE-2019-19645+renameTableSelectCb
CVE-2019-19645+renameUnmapSelectCb
CVE-2019-19646+sqlite3CreateColumnExpr
CVE-2019-19924+codeCompare
CVE-2019-19924+sqlite3WindowRewrite
CVE-2020-13632+fts3ExprLHits
CVE-2021-20294+print_dynamic_symbol
CVE-2021-36690+idxGetTableInfo
CVE-2021-45078+stab_xcoff_builtin_type
CVE-2022-23308+xmlValidNormalizeAttributeValue
CVE-2022-29824+xmlBufCreateSize
CVE-2022-3358+evp_cipher_init_internal
CVE-2022-3786+ossl_a2ulabel
CVE-2022-3996+ossl_policy_cache_set_mapping
CVE-2022-40303+xmlParseAttValueComplex
CVE-2022-40303+xmlParseAttValueInternal
CVE-2022-40303+xmlParseCDSect
CVE-2022-40303+xmlParseCommentComplex
CVE-2022-40303+xmlParseComment
CVE-2022-40303+xmlParseEntityValue
CVE-2022-40303+xmlParseNameComplex
CVE-2022-40303+xmlParseName
CVE-2022-40303+xmlParseNCNameComplex
CVE-2022-40303+xmlParseNCName
CVE-2022-40303+xmlParseNmtoken
CVE-2022-40303+xmlParsePI
CVE-2022-40303+xmlParsePubidLiteral
CVE-2022-40303+xmlParseStringName
CVE-2022-40303+xmlParseSystemLiteral
CVE-2022-48063+load_specific_debug_section
CVE-2022-48065+find_abstract_instance
CVE-2023-0401+pkcs7_bio_add_digest
CVE-2023-25586+bfd_init_section_decompress_status
CVE-2023-45322+xmlStaticCopyNodeList
CVE-2023-5363+evp_cipher_init_internal
CVE-2023-5678+generate_key
CVE-2023-5678+ossl_dh_compute_key
CVE-2024-0727+newpass_p12
CVE-2024-0727+pkcs12_gen_mac
CVE-2024-0727+PKCS12_unpack_authsafes
CVE-2024-0727+PKCS12_unpack_p7data
CVE-2024-0727+PKCS12_unpack_p7encdata
CVE-2024-0727+SMIME_write_PKCS7
CVE-2025-0840+main
CVE-2025-1176+_bfd_elf_gc_mark_rsec
CVE-2025-1176+bfd_elf_reloc_symbol_deleted_p
CVE-2025-1176+_bfd_elf_section_for_symbol
CVE-2025-1181+_bfd_elf_get_link_hash_entry
CVE-2025-1181+elf_link_input_bfd
CVE-2025-29088+setupLookaside
```
