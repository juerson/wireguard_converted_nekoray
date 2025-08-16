import base64
import re
import ast


def is_valid_base64_4chars(s: str) -> bool:
    """判断是否是合法的 4 字符 Base64 字符串"""
    if not re.fullmatch(r"[A-Za-z0-9+/=]{4}", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def base64_reserved(s: str) -> str:
    s = s.strip()
    # 如果原来就是合法的 4 字符 Base64
    if is_valid_base64_4chars(s):
        return s
    # 如果是带中括号的数组格式
    if s.startswith("[") and s.endswith("]"):
        try:
            lst = ast.literal_eval(s)
            if isinstance(lst, list) and all(isinstance(i, int) for i in lst):
                b64_str = base64.b64encode(bytes(lst)).decode("ascii")
                return b64_str if is_valid_base64_4chars(b64_str) else ""
        except ValueError:
            return ""
    # 其它情况
    return ""


if __name__ == '__main__':
    input = " [251, 2, 166] "
    print(base64_reserved(input))
