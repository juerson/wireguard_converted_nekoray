import base64


# 输入字符串格式: "121,102,72"
def encode_from_decimal_str(s: str) -> str:
    nums = [int(x.strip()) for x in s.split(",")]
    b = bytes(nums)
    return base64.b64encode(b).decode("ascii")


# 或者直接传入整数数组
def encode_from_u8_array(arr: list[int]) -> str:
    return base64.b64encode(bytes(arr)).decode("ascii")


# Base64 还原成十进制数组
def decode_to_decimal_str(b64_str: str) -> str:
    b = base64.b64decode(b64_str)
    return ",".join(str(x) for x in b)


# Base64 还原成整数数组
def decode_to_u8_array(b64_str: str) -> list[int]:
    b = base64.b64decode(b64_str)
    return list(b)


if __name__ == "__main__":
    input_str = "251,2,166"
    result = encode_from_decimal_str(input_str)
    print("结果:", result)  # +wKm

    arr = [251, 2, 166]
    result2 = encode_from_u8_array(arr)
    print("数组结果:", result2)  # +wKm

    b64_input = "+wKm"
    # 还原成逗号分隔字符串
    decimal_str = decode_to_decimal_str(b64_input)
    print("还原字符串:", decimal_str)  # 251,2,166
    # 还原成数组
    arr = decode_to_u8_array(b64_input)
    print("还原数组:", arr)  # [251, 2, 166]
