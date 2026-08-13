from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

SPACE = " "
TAB = "\t"
LF = "\n"


@dataclass(frozen=True)
class WhitespaceResult:
    operation: str
    input_path: str | None
    output_path: str
    output_paths: list[str]
    instructions: int
    steps: int
    stdout: str
    written_bytes: int
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _Instruction:
    op: str
    arg: int | str | None = None


def run_whitespace(
    input_path: Path,
    output_path: Path | None = None,
    *,
    input_data: str = "",
    max_steps: int = 1_000_000,
) -> WhitespaceResult:
    """Run a Whitespace esolang program hidden in a text file."""

    _check_file(input_path, "Whitespace 文件")
    if max_steps <= 0:
        raise ValueError("max_steps 必须大于 0")
    source = input_path.read_text(encoding="utf-8", errors="ignore")
    instructions = parse_whitespace(source)
    stdout, stdout_bytes, steps = execute_whitespace(instructions, input_data=input_data, max_steps=max_steps)
    written = 0
    resolved_output = "-"
    output_paths: list[str] = []
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(stdout_bytes)
        written = len(stdout_bytes)
        resolved_output = str(output_path)
        output_paths = [str(output_path)]
    return WhitespaceResult(
        operation="text.whitespace.run",
        input_path=str(input_path),
        output_path=resolved_output,
        output_paths=output_paths,
        instructions=len(instructions),
        steps=steps,
        stdout=stdout,
        written_bytes=written,
    )


def encode_whitespace_text(
    output_path: Path,
    *,
    text: str | None = None,
    payload_path: Path | None = None,
) -> WhitespaceResult:
    """Create a Whitespace program that prints UTF-8 text or payload bytes."""

    if text is None and payload_path is None:
        raise ValueError("whitespace encode 需要 --text 或 --payload")
    if text is not None and payload_path is not None:
        raise ValueError("whitespace encode 只能指定 --text 或 --payload 之一")
    input_label: str | None = None
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        payload = payload_path.read_bytes()
        input_label = str(payload_path)
    else:
        assert text is not None
        payload = text.encode("utf-8")
    program = make_print_program(payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(program, encoding="utf-8")
    return WhitespaceResult(
        operation="text.whitespace.encode",
        input_path=input_label,
        output_path=str(output_path),
        output_paths=[str(output_path)],
        instructions=len(parse_whitespace(program)),
        steps=0,
        stdout="",
        written_bytes=len(program.encode("utf-8")),
    )


def render_whitespace(
    input_path: Path,
    output_path: Path,
    *,
    style: str = "stl",
) -> WhitespaceResult:
    """Write a visible representation of meaningful Whitespace characters."""

    _check_file(input_path, "Whitespace 文件")
    if style not in {"stl", "unicode"}:
        raise ValueError("style 必须是 stl 或 unicode")
    source = input_path.read_text(encoding="utf-8", errors="ignore")
    if style == "stl":
        mapping = {SPACE: "S", TAB: "T", LF: "L\n"}
    else:
        mapping = {SPACE: "·", TAB: "⇥", LF: "↵\n"}
    visible = "".join(mapping[ch] for ch in _meaningful(source))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(visible, encoding="utf-8")
    return WhitespaceResult(
        operation="text.whitespace.show",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        instructions=len(parse_whitespace(source)),
        steps=0,
        stdout="",
        written_bytes=len(visible.encode("utf-8")),
    )


def parse_whitespace(source: str) -> list[_Instruction]:
    code = "".join(_meaningful(source))
    pos = 0
    instructions: list[_Instruction] = []
    while pos < len(code):
        char = code[pos]
        pos += 1
        if char == SPACE:
            if pos >= len(code):
                raise ValueError("不完整的 stack 指令")
            op = code[pos]
            pos += 1
            if op == SPACE:
                number, pos = _read_number(code, pos)
                instructions.append(_Instruction("push", number))
            elif op == LF:
                if pos >= len(code):
                    raise ValueError("不完整的 stack/LF 指令")
                sub = code[pos]
                pos += 1
                if sub == SPACE:
                    instructions.append(_Instruction("dup"))
                elif sub == TAB:
                    instructions.append(_Instruction("swap"))
                elif sub == LF:
                    instructions.append(_Instruction("drop"))
                else:
                    raise ValueError("未知 stack/LF 指令")
            elif op == TAB:
                if pos >= len(code):
                    raise ValueError("不完整的 stack/TAB 指令")
                sub = code[pos]
                pos += 1
                number, pos = _read_number(code, pos)
                if sub == SPACE:
                    instructions.append(_Instruction("copy", number))
                elif sub == LF:
                    instructions.append(_Instruction("slide", number))
                else:
                    raise ValueError("未知 stack/TAB 指令")
            else:
                raise ValueError("未知 stack 指令")
        elif char == TAB:
            if pos >= len(code):
                raise ValueError("不完整的 TAB IMP")
            imp = code[pos]
            pos += 1
            if imp == SPACE:
                op, pos = _read_fixed(code, pos, 2, "arithmetic")
                arithmetic = {
                    SPACE + SPACE: "add",
                    SPACE + TAB: "sub",
                    SPACE + LF: "mul",
                    TAB + SPACE: "div",
                    TAB + TAB: "mod",
                }
                if op not in arithmetic:
                    raise ValueError("未知 arithmetic 指令")
                instructions.append(_Instruction(arithmetic[op]))
            elif imp == TAB:
                op, pos = _read_fixed(code, pos, 1, "heap")
                if op == SPACE:
                    instructions.append(_Instruction("store"))
                elif op == TAB:
                    instructions.append(_Instruction("retrieve"))
                else:
                    raise ValueError("未知 heap 指令")
            elif imp == LF:
                op, pos = _read_fixed(code, pos, 2, "IO")
                io = {
                    SPACE + SPACE: "out_char",
                    SPACE + TAB: "out_num",
                    TAB + SPACE: "read_char",
                    TAB + TAB: "read_num",
                }
                if op not in io:
                    raise ValueError("未知 IO 指令")
                instructions.append(_Instruction(io[op]))
            else:
                raise ValueError("未知 TAB IMP")
        elif char == LF:
            op, pos = _read_fixed(code, pos, 2, "flow")
            if op == SPACE + SPACE:
                label, pos = _read_label(code, pos)
                instructions.append(_Instruction("label", label))
            elif op == SPACE + TAB:
                label, pos = _read_label(code, pos)
                instructions.append(_Instruction("call", label))
            elif op == SPACE + LF:
                label, pos = _read_label(code, pos)
                instructions.append(_Instruction("jump", label))
            elif op == TAB + SPACE:
                label, pos = _read_label(code, pos)
                instructions.append(_Instruction("jump_zero", label))
            elif op == TAB + TAB:
                label, pos = _read_label(code, pos)
                instructions.append(_Instruction("jump_negative", label))
            elif op == TAB + LF:
                instructions.append(_Instruction("return"))
            elif op == LF + LF:
                instructions.append(_Instruction("end"))
            else:
                raise ValueError("未知 flow 指令")
    return instructions


def execute_whitespace(
    instructions: list[_Instruction], *, input_data: str = "", max_steps: int = 1_000_000) -> tuple[str, bytes, int]:
    labels: dict[str, int] = {}
    for index, instruction in enumerate(instructions):
        if instruction.op == "label":
            label = str(instruction.arg)
            if label in labels:
                raise ValueError(f"重复标签：{_label_repr(label)}")
            labels[label] = index
    stack: list[int] = []
    heap: dict[int, int] = {}
    calls: list[int] = []
    output: list[str] = []
    output_bytes = bytearray()
    input_pos = 0
    pc = 0
    steps = 0
    while pc < len(instructions):
        steps += 1
        if steps > max_steps:
            raise ValueError(f"Whitespace 超过最大步数：{max_steps}")
        instruction = instructions[pc]
        pc += 1
        op = instruction.op
        arg = instruction.arg
        if op == "push":
            stack.append(int(arg))
        elif op == "dup":
            stack.append(_peek(stack))
        elif op == "copy":
            n = int(arg)
            if n < 0:
                raise ValueError("copy 参数不能为负")
            if n >= len(stack):
                raise ValueError("copy 栈深度不足")
            stack.append(stack[-1 - n])
        elif op == "swap":
            _require_stack(stack, 2, "swap")
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == "drop":
            _pop(stack, "drop")
        elif op == "slide":
            n = int(arg)
            if n < 0:
                raise ValueError("slide 参数不能为负")
            top = _pop(stack, "slide")
            if n:
                del stack[-n:]
            stack.append(top)
        elif op in {"add", "sub", "mul", "div", "mod"}:
            right = _pop(stack, op)
            left = _pop(stack, op)
            if op == "add":
                stack.append(left + right)
            elif op == "sub":
                stack.append(left - right)
            elif op == "mul":
                stack.append(left * right)
            elif op == "div":
                if right == 0:
                    raise ValueError("除数为 0")
                stack.append(left // right)
            else:
                if right == 0:
                    raise ValueError("模数为 0")
                stack.append(left % right)
        elif op == "store":
            value = _pop(stack, "store")
            address = _pop(stack, "store")
            heap[address] = value
        elif op == "retrieve":
            address = _pop(stack, "retrieve")
            stack.append(heap.get(address, 0))
        elif op == "label":
            continue
        elif op == "call":
            calls.append(pc)
            pc = _label_target(labels, str(arg))
        elif op == "jump":
            pc = _label_target(labels, str(arg))
        elif op == "jump_zero":
            if _pop(stack, "jump_zero") == 0:
                pc = _label_target(labels, str(arg))
        elif op == "jump_negative":
            if _pop(stack, "jump_negative") < 0:
                pc = _label_target(labels, str(arg))
        elif op == "return":
            if not calls:
                raise ValueError("return 调用栈为空")
            pc = calls.pop()
        elif op == "end":
            break
        elif op == "out_char":
            value = _pop(stack, "out_char")
            if value < 0 or value > 0x10FFFF:
                raise ValueError(f"字符码点越界：{value}")
            char = chr(value)
            output.append(char)
            if value <= 0xFF:
                output_bytes.append(value)
            else:
                output_bytes.extend(char.encode("utf-8"))
        elif op == "out_num":
            number_text = str(_pop(stack, "out_num"))
            output.append(number_text)
            output_bytes.extend(number_text.encode("utf-8"))
        elif op == "read_char":
            address = _pop(stack, "read_char")
            if input_pos >= len(input_data):
                heap[address] = -1
            else:
                heap[address] = ord(input_data[input_pos])
                input_pos += 1
        elif op == "read_num":
            address = _pop(stack, "read_num")
            while input_pos < len(input_data) and input_data[input_pos].isspace():
                input_pos += 1
            start = input_pos
            while input_pos < len(input_data) and not input_data[input_pos].isspace():
                input_pos += 1
            token = input_data[start:input_pos]
            heap[address] = int(token) if token else 0
        else:
            raise ValueError(f"未知指令：{op}")
    return "".join(output), bytes(output_bytes), steps


def make_print_program(data: bytes) -> str:
    chunks: list[str] = []
    for byte in data:
        chunks.append(_push_number(byte))
        chunks.append(TAB + LF + SPACE + SPACE)
    chunks.append(LF + LF + LF)
    return "".join(chunks)


def _push_number(value: int) -> str:
    sign = SPACE if value >= 0 else TAB
    magnitude = abs(value)
    bits = "" if magnitude == 0 else bin(magnitude)[2:].replace("0", SPACE).replace("1", TAB)
    return SPACE + SPACE + sign + bits + LF


def _read_number(code: str, pos: int) -> tuple[int, int]:
    if pos >= len(code):
        raise ValueError("数字缺少符号")
    sign_char = code[pos]
    if sign_char not in {SPACE, TAB}:
        raise ValueError("数字符号必须为空格或 Tab")
    pos += 1
    bits: list[str] = []
    while pos < len(code) and code[pos] != LF:
        if code[pos] not in {SPACE, TAB}:
            raise ValueError("数字位必须为空格或 Tab")
        bits.append("1" if code[pos] == TAB else "0")
        pos += 1
    if pos >= len(code):
        raise ValueError("数字缺少 LF 终止符")
    pos += 1
    value = int("".join(bits), 2) if bits else 0
    return (-value if sign_char == TAB else value), pos


def _read_label(code: str, pos: int) -> tuple[str, int]:
    start = pos
    while pos < len(code) and code[pos] != LF:
        if code[pos] not in {SPACE, TAB}:
            raise ValueError("标签只能包含空格或 Tab")
        pos += 1
    if pos >= len(code):
        raise ValueError("标签缺少 LF 终止符")
    return code[start:pos], pos + 1


def _read_fixed(code: str, pos: int, count: int, label: str) -> tuple[str, int]:
    end = pos + count
    if end > len(code):
        raise ValueError(f"不完整的 {label} 指令")
    return code[pos:end], end


def _meaningful(source: str):  # type: ignore[no-untyped-def]
    for char in source:
        if char in {SPACE, TAB, LF}:
            yield char


def _pop(stack: list[int], op: str) -> int:
    if not stack:
        raise ValueError(f"{op} 栈为空")
    return stack.pop()


def _peek(stack: list[int]) -> int:
    if not stack:
        raise ValueError("dup 栈为空")
    return stack[-1]


def _require_stack(stack: list[int], count: int, op: str) -> None:
    if len(stack) < count:
        raise ValueError(f"{op} 栈深度不足：需要 {count}，当前 {len(stack)}")


def _label_target(labels: dict[str, int], label: str) -> int:
    if label not in labels:
        raise ValueError(f"未知标签：{_label_repr(label)}")
    return labels[label]


def _label_repr(label: str) -> str:
    return label.replace(SPACE, "S").replace(TAB, "T")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
