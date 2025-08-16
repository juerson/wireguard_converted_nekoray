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


def to_base64_if_4chars_strict(s: str) -> str:
    """
    正向转换：
    带中括号的数组 -> Base64 (长度4)
    原本就是4字符合法Base64 -> 返回原值
    其他情况 -> 返回空字符串
    """
    s = s.strip()
    # 如果原来就是合法的 4 字符 Base64
    if is_valid_base64_4chars(s):
        return s
    # 如果是带中括号的数组格式
    if s.startswith("[") and s.endswith("]"):
        try:
            # 支持有空格或没有空格的逗号分隔
            nums = [int(x) for x in s[1:-1].split(",")]
            b64_str = base64.b64encode(bytes(nums)).decode("ascii")
            return b64_str if is_valid_base64_4chars(b64_str) else ""
        except ValueError:
            return ""
    # 其它情况
    return ""


def from_base64_4chars_to_list(s: str) -> list[int]:
    """
    反向转换：
    - 4字符合法Base64 -> list[int]
    - "[121, 102, 72]" -> list[int]
    - 其他情况 -> []
    """
    s = s.strip()

    # 优先判断是否是 [n, n, n] 形式
    if s.startswith("[") and s.endswith("]"):
        try:
            lst = ast.literal_eval(s)  # 安全解析
            if isinstance(lst, list) and all(isinstance(x, int) for x in lst):
                return lst
        except (ValueError, SyntaxError):
            return []
        return []

    # 如果是4字符合法base64
    if is_valid_base64_4chars(s):
        try:
            decoded_bytes = base64.b64decode(s)
            return list(decoded_bytes)
        except Exception:
            return []

    return []


if __name__ == "__main__":
    # 测试正向转换
    inputs = [
        "[251, 2, 166]",
        "[121,102,72]",
        "eWZI",
        "[1,2,3]",
        "abcd",
        "YWJj"
    ]

    print("=== 正向转换 ===")
    for t in inputs:
        print(f"{t} -> '{to_base64_if_4chars_strict(t)}'")

    print("\n=== 反向转换 ===")
    b64_tests = ["eWZI", "YWJj", "abcd", "1234", "[121, 102, 72]"]
    for b64 in b64_tests:
        print(f"{b64} -> {from_base64_4chars_to_list(b64)}")
