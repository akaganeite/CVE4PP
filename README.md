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

# Adjustment in target versions
## binutils
- failed to compile
  - 2.40 O1
  - 2.23.1 O0
  - 2.23.2 O0
## openssl
### failed to compile
- gcc/o0
  - OpenSSL-fips-2_0_11 openssl
  - OpenSSL_1_0_0q
  - OpenSSL_1_0_1i
  - OpenSSL_1_0_1l
  - OpenSSL_1_0_2a
  - OpenSSL_1_0_2c
  - OpenSSL_0_9_8zg
  - OpenSSL_1_1_0
  - OpenSSL_1_1_0a
  - OpenSSL_1_1_0-pre5
  - OpenSSL_1_1_0-pre6
  - OpenSSL_1_1_0b
  - OpenSSL_1_0_0t
  - openssl-3.0.0-alpha1
  - OpenSSL_1_1_0c
  - OpenSSL_1_1_0d
  - adjust target binary
    - openssl-OpenSSL_1_0_0r-o0-openssl -> openssl-OpenSSL_1_0_0r-o0-libcrypto
    - openssl-OpenSSL-fips-2_0_13-o0-openssl  ->  openssl-OpenSSL-fips-2_0_13-o0-libcrypto
    - （CVE-2016-2108）openssl-OpenSSL_1_0_0s-o0-openssl  -> openssl-OpenSSL_1_0_0s-o0-libcrypto
    - （others）openssl-OpenSSL_1_0_0s-o0-openssl  -> openssl-OpenSSL_1_0_0s-o0-libssl
    - openssl-OpenSSL_1_0_1j-o0-openssl ->  openssl-OpenSSL_1_0_1j-o0-libssl
    - openssl-OpenSSL_1_0_1k-o0-openssl ->  openssl-OpenSSL_1_0_1k-o0-libssl
    - openssl-OpenSSL_1_0_2b-o0-openssl ->  openssl-OpenSSL_1_0_2b-o0-libcrypto
    - openssl-OpenSSL_1_0_0o-o0-openssl -> openssl-OpenSSL_1_0_0o-o0-libssl
    - openssl-OpenSSL_1_0_0p-o0-openssl -> openssl-OpenSSL_1_0_0p-o0-libssl
    - openssl-OpenSSL_1_0_1n-o0-openssl -> openssl-OpenSSL_1_0_1n-o0-libssl
    - openssl-OpenSSL_1_0_1o-o0-openssl -> openssl-OpenSSL_1_0_1o-o0-libssl
    - openssl-OpenSSL_1_0_2-o0-openssl -> openssl-OpenSSL_1_0_2-o0-libssl
- gcc/o1(whats more compared to O0)
  - OpenSSL_1_0_2b
  - OpenSSL-fips-2_0_13-libcrypto && openssl
- gcc/o2
  - OpenSSL_1_0_0s-o2-libcrypto

## curl
- failed to compile
  - <7.29.0
## ffmpeg
- fail to compile
  - 3.2.16
## sqlite
- fail to compile
  - 3.14

# Case Study Candidates
- CVE-2022-42916 create_conn ，partial fail ok
  - patch为pure deletion，后续添加代码和deletion部分有些类似
  - patch discovery all-succ，PS3和BinXray有false negative
- CVE-2019-19244 sqlite3Select ok
  - 使用`#ifndef`,`#idefine`的条件编译
- CVE-2019-19880 exprListAppendList ok
  -  v3.32.0有func upgrade 更改了代码看起来的样子，只有BinXray有问题。。。
- CVE-2021-36690 ok
  -  挺有意思的，新增变量和对新增变量的操作 只有BinXray有问题。。。
- CVE-2020-16590
  - 只更改了赋值语句的变量名
- CVE-2018-1000120
  - 只修改了函数调用中的一个参数
- CVE-2022-29824
  - 部分work fail
-  CVE-2015-7500
  -  只更改了变量声明
-   CVE-2019-5435
  - React 无输出
- CVE-2022-3786 ok
  - trivial 更改
  - insight patch presence需要有diff parser与审查工具，否则还是需要人力介入，没什么实际作用
-  CVE-2022-46908 ok
  -  safemodeauth 的更改太trivial，只涉及全局变量
- CVE-2020-22043
  - goto->return

- CVE-2022-48065 只有REACT可以正确检测
- trivial modification
  - CVE-2022-0284
  - CVE-2020-25667
  - CVE-2017-12894
- 语句挪地方
  -  CVE-2019-16711
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
- ffmpeg:16/59 | 21/381=5.5%
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
ffmpeg:
"CVE-2020-21697+mpeg_mux_write_packet",
"CVE-2020-24020+dnn_execute_layer_conv2d",
"CVE-2020-24020+dnn_execute_layer_math_binary",
"CVE-2020-24020+dnn_execute_layer_math_unary",
"CVE-2020-24020+dnn_execute_layer_maximum",
"CVE-2020-24020+dnn_execute_layer_pad",
"CVE-2020-22038+ff_v4l2_m2m_codec_end",
"CVE-2020-22038+v4l2_decode_init",
"CVE-2020-22021+filter_edges",
"CVE-2020-22046+ff_ac3_encode_close",
"CVE-2020-22019+ff_vmafmotion_init",
"CVE-2020-22039+avi_write_trailer",
"CVE-2020-22029+slice_get_derivative",
"CVE-2020-22037+ff_frame_thread_encoder_init",
"CVE-2022-1475+g729_parse",
"CVE-2020-20896+latm_write_packet"
```
