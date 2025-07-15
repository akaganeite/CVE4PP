from pygments import lexer
from unidiff import PatchSet, PatchedFile, Hunk
from pygments.lexers import get_lexer_by_name
from pygments.token import Token
import re

def get_function_name_lexer(section_header: str) -> str | None:
        """使用词法分析器提取函数名（备用方法）"""
        lexer = get_lexer_by_name('c')
        tokens = list(lexer.get_tokens(section_header))
        
        # 寻找函数名模式：标识符后跟左括号
        for i, token in enumerate(tokens):
            if (token[0] == Token.Name and 
                i + 1 < len(tokens) and 
                tokens[i + 1][0] == Token.Punctuation and 
                tokens[i + 1][1] == '('):
                
                func_name = token[1]
                # 检查是否为关键字
                if not is_c_keyword(func_name):
                    return func_name
        
        # 处理函数名和左括号之间有空格的情况
        for i, token in enumerate(tokens):
            if (token[0] == Token.Name and 
                i + 2 < len(tokens) and 
                tokens[i + 1][0] == Token.Text.Whitespace and
                tokens[i + 2][0] == Token.Punctuation and 
                tokens[i + 2][1] == '('):
                
                func_name = token[1]
                if not is_c_keyword(func_name):
                    return func_name
        
        return None

def is_c_keyword(word: str) -> bool:
    """检查是否为C关键字"""
    c_keywords = {
        'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
        'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
        'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static',
        'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while',
        'inline', 'restrict', '_Bool', '_Complex', '_Imaginary'
    }
    return word.lower() in c_keywords

def get_function_name(section_header: str) :
    """
    从diff section header中提取函数名
    支持以下格式：
    - xmlStringLenDecodeEntities(xmlParserCtxtPtr ctxt, const xmlChar *str, int len,
    - _bfd_coff_read_string_table (bfd *abfd)
    - 标准C函数声明
    """
    # 首先尝试使用正则表达式提取函数名
    
    # 匹配函数名模式：标识符后跟左括号，可能包含参数
    # 处理函数名和左括号之间可能有空格的情况
    patterns = [
        # 标准格式：function_name(
        r'(\w+)\s*\(',
        # 处理带下划线的函数名
        r'(_\w+)\s*\(',
        # 处理带数字的函数名
        r'(\w+\d*)\s*\(',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, section_header)
        if match:
            func_name = match.group(1)
            # 验证这是一个有效的函数名（不是关键字）
            if not is_c_keyword(func_name):
                return func_name
    
    # 如果正则表达式失败，回退到词法分析
    return get_function_name_lexer(section_header)


def parse_patchfile(patch_file: PatchedFile) -> dict:
    dic = {}
    print("patch_file_path", patch_file.path)
    dic['path'] = patch_file.path
    dic['functions'] = {}
    for hook in patch_file:
        print("section_header", hook.section_header)
        function_name = get_function_name(hook.section_header)
        print("function_name", function_name)
        if function_name is not None:
            if function_name not in dic['functions']:
                dic['functions'][function_name] = []
            dic['functions'][function_name].append(hook)
    return dic


def parse_diff(diff):
    l = []
    patch = PatchSet.from_filename(diff)
    # filter not c/c++ run file, support C now, but actually support all binary file compiled
    patch = [file for file in patch if file.path.endswith(".c")]
    for file in patch:
        parse_res = parse_patchfile(file)
        if parse_res is not None:
            l.append(parse_res)
    return l

print("aaa")
parse_diff("binutils_CVE-2018-1000876_3a551c7a1b80.diff")