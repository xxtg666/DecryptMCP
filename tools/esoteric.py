import re


def register(mcp):

    @mcp.tool()
    def brainfuck_execute(code: str, input_data: str = "") -> str:
        """Brainfuck解释执行。code: BF代码，input_data: 输入数据"""
        try:
            tape = [0] * 30000
            ptr = 0
            pc = 0
            output = []
            input_idx = 0
            steps = 0
            max_steps = 1000000

            brackets = {}
            stack = []
            for i, ch in enumerate(code):
                if ch == '[':
                    stack.append(i)
                elif ch == ']':
                    if stack:
                        j = stack.pop()
                        brackets[j] = i
                        brackets[i] = j

            while pc < len(code) and steps < max_steps:
                cmd = code[pc]
                if cmd == '>':
                    ptr = (ptr + 1) % 30000
                elif cmd == '<':
                    ptr = (ptr - 1) % 30000
                elif cmd == '+':
                    tape[ptr] = (tape[ptr] + 1) % 256
                elif cmd == '-':
                    tape[ptr] = (tape[ptr] - 1) % 256
                elif cmd == '.':
                    output.append(chr(tape[ptr]))
                elif cmd == ',':
                    if input_idx < len(input_data):
                        tape[ptr] = ord(input_data[input_idx])
                        input_idx += 1
                    else:
                        tape[ptr] = 0
                elif cmd == '[':
                    if tape[ptr] == 0:
                        pc = brackets.get(pc, pc)
                elif cmd == ']':
                    if tape[ptr] != 0:
                        pc = brackets.get(pc, pc)
                pc += 1
                steps += 1

            result = "".join(output)
            if steps >= max_steps:
                result += "\n[警告: 达到最大执行步数限制]"
            return result
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def brainfuck_encode(text: str) -> str:
        """将文本编码为Brainfuck代码"""
        try:
            code = []
            prev = 0
            for ch in text:
                val = ord(ch)
                diff = val - prev
                if diff > 0:
                    code.append('+' * diff)
                elif diff < 0:
                    code.append('-' * (-diff))
                code.append('.')
                prev = val
            return "".join(code)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def ook_cipher(code: str, mode: str = "decode") -> str:
        """Ook!语言解释/转换。mode: decode(Ook->文本)/from_bf(BF->Ook)/to_bf(Ook->BF)"""
        try:
            if mode == "to_bf":
                tokens = re.findall(r'Ook[.!?]', code)
                bf_map = {
                    ('Ook.', 'Ook.'): '>',
                    ('Ook!', 'Ook!'): '<',
                    ('Ook.', 'Ook!'): '+',
                    ('Ook!', 'Ook.'): '-',
                    ('Ook!', 'Ook?'): '.',
                    ('Ook?', 'Ook!'): ',',
                    ('Ook?', 'Ook?'): '[',
                    ('Ook.', 'Ook?') : ']',  # nonstandard but common
                }
                # Also handle standard ] mapping
                bf_map[('Ook?', 'Ook.')] = ']'
                bf = []
                for i in range(0, len(tokens) - 1, 2):
                    pair = (tokens[i], tokens[i+1])
                    bf.append(bf_map.get(pair, ''))
                return "".join(bf)
            elif mode == "from_bf":
                bf_to_ook = {
                    '>': 'Ook. Ook. ',
                    '<': 'Ook! Ook! ',
                    '+': 'Ook. Ook! ',
                    '-': 'Ook! Ook. ',
                    '.': 'Ook! Ook? ',
                    ',': 'Ook? Ook! ',
                    '[': 'Ook? Ook? ',
                    ']': 'Ook? Ook. ',
                }
                return "".join(bf_to_ook.get(c, '') for c in code)
            else:
                bf = ook_cipher(code, "to_bf")
                return brainfuck_execute(bf)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def nato_phonetic(text: str, mode: str = "encode") -> str:
        """NATO音标字母表转换。mode: encode(字母->音标)/decode(音标->字母)"""
        try:
            NATO = {
                'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta',
                'E': 'Echo', 'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel',
                'I': 'India', 'J': 'Juliet', 'K': 'Kilo', 'L': 'Lima',
                'M': 'Mike', 'N': 'November', 'O': 'Oscar', 'P': 'Papa',
                'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
                'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray',
                'Y': 'Yankee', 'Z': 'Zulu',
                '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three',
                '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven',
                '8': 'Eight', '9': 'Niner'
            }
            if mode == "encode":
                result = []
                for ch in text.upper():
                    if ch in NATO:
                        result.append(NATO[ch])
                    elif ch == ' ':
                        result.append('[SPACE]')
                    else:
                        result.append(ch)
                return " ".join(result)
            else:
                REV = {v.upper(): k for k, v in NATO.items()}
                words = text.strip().split()
                result = []
                for w in words:
                    upper = w.upper().rstrip('.,;:')
                    if upper in REV:
                        result.append(REV[upper])
                    elif upper == '[SPACE]':
                        result.append(' ')
                    else:
                        result.append(w)
                return "".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def pig_latin(text: str, mode: str = "encode") -> str:
        """Pig Latin转换。mode: encode/decode"""
        try:
            vowels = set('aeiouAEIOU')
            if mode == "encode":
                words = text.split()
                result = []
                for word in words:
                    if not word[0].isalpha():
                        result.append(word)
                        continue
                    if word[0] in vowels:
                        result.append(word + "way")
                    else:
                        i = 0
                        while i < len(word) and word[i] not in vowels:
                            i += 1
                        result.append(word[i:] + word[:i] + "ay")
                return " ".join(result)
            else:
                words = text.split()
                result = []
                for word in words:
                    if word.endswith("way") and word[0] in vowels:
                        result.append(word[:-3])
                    elif word.endswith("ay"):
                        core = word[:-2]
                        for i in range(len(core) - 1, -1, -1):
                            if core[i] in vowels:
                                result.append(core[i+1:] + core[:i+1])
                                break
                        else:
                            result.append(word)
                    else:
                        result.append(word)
                return " ".join(result)
        except Exception as e:
            return f"错误: {e}"

    @mcp.tool()
    def zero_width_stego(text: str, hidden: str = "", mode: str = "encode") -> str:
        """零宽字符隐写术编解码。mode: encode(将hidden藏入text)/decode(提取隐藏信息)"""
        try:
            ZW_CHARS = ['\u200b', '\u200c', '\u200d', '\ufeff']  # 0,1,分隔,结束
            if mode == "encode":
                if not hidden:
                    return "错误: encode模式需要提供hidden参数"
                encoded = []
                for ch in hidden:
                    bits = format(ord(ch), '08b')
                    for bit in bits:
                        encoded.append(ZW_CHARS[int(bit)])
                    encoded.append(ZW_CHARS[2])
                zw_str = "".join(encoded)
                mid = len(text) // 2
                return text[:mid] + zw_str + text[mid:]
            else:
                zw = [ch for ch in text if ch in ZW_CHARS]
                if not zw:
                    return "未发现零宽字符隐写内容"
                result = []
                bits = []
                for ch in zw:
                    if ch == ZW_CHARS[2]:
                        if bits:
                            byte_val = int("".join(bits), 2)
                            result.append(chr(byte_val))
                            bits = []
                    elif ch == ZW_CHARS[0]:
                        bits.append('0')
                    elif ch == ZW_CHARS[1]:
                        bits.append('1')
                return f"隐藏内容: {''.join(result)}\n零宽字符数量: {len(zw)}"
        except Exception as e:
            return f"错误: {e}"
