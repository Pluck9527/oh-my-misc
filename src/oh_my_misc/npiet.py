"""Native Piet/npiet-compatible image interpreter for CTF challenges."""

from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

PIET_PALETTE: tuple[tuple[int, int, int], ...] = (
    (255, 192, 192),
    (255, 255, 192),
    (192, 255, 192),
    (192, 255, 255),
    (192, 192, 255),
    (255, 192, 255),
    (255, 0, 0),
    (255, 255, 0),
    (0, 255, 0),
    (0, 255, 255),
    (0, 0, 255),
    (255, 0, 255),
    (192, 0, 0),
    (192, 192, 0),
    (0, 192, 0),
    (0, 192, 192),
    (0, 0, 192),
    (192, 0, 192),
)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
_COLOR_TO_INDEX = {color: index for index, color in enumerate(PIET_PALETTE)}
_DIRECTIONS = ((1, 0), (0, 1), (-1, 0), (0, -1))
_DP_NAMES = ("right", "down", "left", "up")
_CC_NAMES = ("left", "right")
_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("nop", "push", "pop"),
    ("add", "subtract", "multiply"),
    ("divide", "mod", "not"),
    ("greater", "pointer", "switch"),
    ("duplicate", "roll", "in-number"),
    ("in-char", "out-number", "out-char"),
)


@dataclass(frozen=True)
class PietTraceStep:
    step: int
    position: tuple[int, int]
    next_position: tuple[int, int]
    dp: str
    cc: str
    command: str
    block_size: int
    stack: list[int]


@dataclass(frozen=True)
class PietResult:
    operation: str
    input_path: str
    output_path: str | None
    output_paths: list[str]
    count: int
    width: int
    height: int
    codel_size: int
    codel_width: int
    codel_height: int
    steps: int
    halted: bool
    halt_reason: str
    stdout: str
    stdout_hex: str
    stack: list[int]
    unknown_codels: int
    trace: list[dict[str, object]] | None = None

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def run_piet(
    input_path: Path,
    *,
    input_data: str = "",
    codel_size: int | None = None,
    max_steps: int = 100_000,
    unknown: str = "white",
    trace: bool = False,
    trace_limit: int = 1_000,
    trace_image_path: Path | None = None,
) -> PietResult:
    """Execute a Piet program image using the standard DP/CC rules."""
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if max_steps < 1:
        raise ValueError("max_steps 必须大于 0")
    if trace_limit < 0:
        raise ValueError("trace_limit 不能小于 0")
    if unknown not in {"white", "black", "error", "nearest"}:
        raise ValueError(f"未知颜色处理方式：{unknown}")

    codels, resolved_codel_size, image_size, unknown_codels = load_piet_codels(
        input_path, codel_size=codel_size, unknown=unknown
    )
    height, width = codels.shape
    if codels[0, 0] == -2:
        return _piet_result(
            input_path,
            image_size,
            resolved_codel_size,
            width,
            height,
            0,
            True,
            "起始 codel 为黑色",
            "",
            [],
            unknown_codels,
            [],
            trace_image_path,
            [],
        )

    components, component_by_codel = _build_components(codels)
    position = (0, 0)
    dp = 0
    cc = 0
    stack: list[int] = []
    output: list[str] = []
    input_stream = _InputStream(input_data)
    trace_steps: list[PietTraceStep] = []
    path: list[tuple[int, int]] = [position]
    if codels[0, 0] == -1:
        initial_move = _move_from_white(codels, position, dp, cc)
        if initial_move is None:
            return _piet_result(
                input_path,
                image_size,
                resolved_codel_size,
                width,
                height,
                0,
                True,
                "起始白色区域无出口",
                "",
                stack,
                unknown_codels,
                trace_steps,
                trace_image_path,
                path,
            )
        position, dp, cc, path = initial_move
    halted = False
    halt_reason = "达到 max_steps"
    steps = 0

    for step_index in range(max_steps):
        current_color = int(codels[position[1], position[0]])
        component = components[component_by_codel[position[1], position[0]]]
        block_size = len(component)
        moved = _leave_colored_block(codels, component, dp, cc)
        if moved is None:
            halted = True
            halt_reason = "连续 8 次移动受阻"
            break
        next_position, next_color, dp, cc, crossed_white, traversed = moved
        command = (
            "white-slide" if crossed_white else _command_for_transition(current_color, next_color)
        )
        _execute_command(command, block_size, stack, input_stream, output)
        # DP/CC commands consume their values inside this explicit branch.
        dp, cc = _apply_direction_command(command, stack, dp, cc)

        steps = step_index + 1
        if trace and len(trace_steps) < trace_limit:
            trace_steps.append(
                PietTraceStep(
                    step=step_index,
                    position=position,
                    next_position=next_position,
                    dp=_DP_NAMES[dp],
                    cc=_CC_NAMES[cc],
                    command=command,
                    block_size=block_size,
                    stack=stack.copy(),
                )
            )
        position = next_position
        path.extend(traversed)
    else:
        halted = False

    return _piet_result(
        input_path,
        image_size,
        resolved_codel_size,
        width,
        height,
        steps,
        halted,
        halt_reason,
        "".join(output),
        stack,
        unknown_codels,
        trace_steps,
        trace_image_path,
        path,
    )


def load_piet_codels(
    input_path: Path, *, codel_size: int | None = None, unknown: str = "white"
) -> tuple[np.ndarray, int, tuple[int, int], int]:
    """Load, downsample and classify an image into Piet palette indexes."""
    with Image.open(input_path) as source:
        rgb = np.asarray(source.convert("RGB"), dtype=np.uint8)
        image_size = source.size
    resolved = detect_codel_size(rgb) if codel_size is None else codel_size
    if resolved < 1:
        raise ValueError("codel_size 必须大于 0")
    if rgb.shape[1] % resolved or rgb.shape[0] % resolved:
        raise ValueError(
            f"图片尺寸 {rgb.shape[1]}×{rgb.shape[0]} 不能被 codel size {resolved} 整除"
        )
    sampled = rgb.reshape(
        rgb.shape[0] // resolved,
        resolved,
        rgb.shape[1] // resolved,
        resolved,
        3,
    )[:, 0, :, 0, :]
    codels = np.empty(sampled.shape[:2], dtype=np.int16)
    unknown_count = 0
    for y in range(sampled.shape[0]):
        for x in range(sampled.shape[1]):
            color = tuple(int(value) for value in sampled[y, x])
            if color in _COLOR_TO_INDEX:
                codels[y, x] = _COLOR_TO_INDEX[color]
            elif color == WHITE:
                codels[y, x] = -1
            elif color == BLACK:
                codels[y, x] = -2
            else:
                unknown_count += 1
                if unknown == "error":
                    raise ValueError(f"未知 Piet 颜色 #{color[0]:02X}{color[1]:02X}{color[2]:02X}")
                if unknown == "black":
                    codels[y, x] = -2
                elif unknown == "nearest":
                    codels[y, x] = _nearest_palette_index(color)
                else:
                    codels[y, x] = -1
    return codels, resolved, image_size, unknown_count


def detect_codel_size(rgb: np.ndarray) -> int:
    """Infer npiet's zoom factor from same-colour run lengths."""
    height, width = rgb.shape[:2]
    run_lengths: list[int] = []
    for row in rgb:
        changes = np.any(row[1:] != row[:-1], axis=1)
        edges = np.flatnonzero(changes) + 1
        run_lengths.extend(np.diff(np.concatenate(([0], edges, [width]))).tolist())
    for column in np.swapaxes(rgb, 0, 1):
        changes = np.any(column[1:] != column[:-1], axis=1)
        edges = np.flatnonzero(changes) + 1
        run_lengths.extend(np.diff(np.concatenate(([0], edges, [height]))).tolist())
    run_lengths = [length for length in run_lengths if length > 0]
    inferred = 0
    for length in run_lengths:
        inferred = math.gcd(inferred, length)
    if inferred < 1 or width % inferred or height % inferred:
        return 1
    return inferred


def _build_components(codels: np.ndarray) -> tuple[list[list[tuple[int, int]]], np.ndarray]:
    height, width = codels.shape
    labels = np.full((height, width), -1, dtype=np.int32)
    components: list[list[tuple[int, int]]] = []
    for y in range(height):
        for x in range(width):
            if codels[y, x] < 0 or labels[y, x] >= 0:
                continue
            color = codels[y, x]
            label = len(components)
            component: list[tuple[int, int]] = []
            queue = deque([(x, y)])
            labels[y, x] = label
            while queue:
                current = queue.popleft()
                component.append(current)
                for dx, dy in _DIRECTIONS:
                    nx, ny = current[0] + dx, current[1] + dy
                    if (
                        0 <= nx < width
                        and 0 <= ny < height
                        and labels[ny, nx] < 0
                        and codels[ny, nx] == color
                    ):
                        labels[ny, nx] = label
                        queue.append((nx, ny))
            components.append(component)
    return components, labels


def _leave_colored_block(
    codels: np.ndarray,
    component: list[tuple[int, int]],
    dp: int,
    cc: int,
) -> tuple[tuple[int, int], int, int, int, bool, list[tuple[int, int]]] | None:
    for attempt in range(8):
        exit_codel = _select_exit(component, dp, cc)
        dx, dy = _DIRECTIONS[dp]
        target = (exit_codel[0] + dx, exit_codel[1] + dy)
        if _inside(codels, target) and codels[target[1], target[0]] != -2:
            if codels[target[1], target[0]] == -1:
                slid = _traverse_white(codels, target, dp, cc)
                if slid is None:
                    return None
                destination, dp, cc, white_path = slid
                return (
                    destination,
                    int(codels[destination[1], destination[0]]),
                    dp,
                    cc,
                    True,
                    white_path,
                )
            else:
                return target, int(codels[target[1], target[0]]), dp, cc, False, [target]
        if attempt % 2 == 0:
            cc = 1 - cc
        else:
            dp = (dp + 1) % 4
    return None


def _move_from_white(
    codels: np.ndarray, position: tuple[int, int], dp: int, cc: int
) -> tuple[tuple[int, int], int, int, list[tuple[int, int]]] | None:
    return _traverse_white(codels, position, dp, cc)


def _traverse_white(
    codels: np.ndarray, position: tuple[int, int], dp: int, cc: int
) -> tuple[tuple[int, int], int, int, list[tuple[int, int]]] | None:
    """Follow Piet 1.2 white-codel rules, including turns inside white regions."""
    visited: set[tuple[tuple[int, int], int, int]] = set()
    current = position
    path = [position]
    while (current, dp, cc) not in visited:
        visited.add((current, dp, cc))
        dx, dy = _DIRECTIONS[dp]
        target = current[0] + dx, current[1] + dy
        while _inside(codels, target) and codels[target[1], target[0]] == -1:
            state = (target, dp, cc)
            if state in visited:
                return None
            visited.add(state)
            current = target
            path.append(current)
            target = current[0] + dx, current[1] + dy
        if _inside(codels, target) and codels[target[1], target[0]] != -2:
            path.append(target)
            return target, dp, cc, path
        cc = 1 - cc
        dp = (dp + 1) % 4
    return None


def _select_exit(component: list[tuple[int, int]], dp: int, cc: int) -> tuple[int, int]:
    if dp == 0:
        edge = max(x for x, _ in component)
        candidates = [(x, y) for x, y in component if x == edge]
        return (
            min(candidates, key=lambda point: point[1])
            if cc == 0
            else max(candidates, key=lambda point: point[1])
        )
    if dp == 1:
        edge = max(y for _, y in component)
        candidates = [(x, y) for x, y in component if y == edge]
        return (
            max(candidates, key=lambda point: point[0])
            if cc == 0
            else min(candidates, key=lambda point: point[0])
        )
    if dp == 2:
        edge = min(x for x, _ in component)
        candidates = [(x, y) for x, y in component if x == edge]
        return (
            max(candidates, key=lambda point: point[1])
            if cc == 0
            else min(candidates, key=lambda point: point[1])
        )
    edge = min(y for _, y in component)
    candidates = [(x, y) for x, y in component if y == edge]
    return (
        min(candidates, key=lambda point: point[0])
        if cc == 0
        else max(candidates, key=lambda point: point[0])
    )


def _command_for_transition(current: int, target: int) -> str:
    current_hue, current_lightness = current % 6, current // 6
    target_hue, target_lightness = target % 6, target // 6
    return _COMMANDS[(target_hue - current_hue) % 6][(target_lightness - current_lightness) % 3]


def _execute_command(
    command: str,
    block_size: int,
    stack: list[int],
    input_stream: _InputStream,
    output: list[str],
) -> None:
    if command == "push":
        stack.append(block_size)
    elif command == "pop" and stack:
        stack.pop()
    elif command in {"add", "subtract", "multiply", "divide", "mod", "greater"}:
        if len(stack) < 2:
            return
        top = stack.pop()
        second = stack.pop()
        if command in {"divide", "mod"} and top == 0:
            stack.extend((second, top))
            return
        operations = {
            "add": lambda: second + top,
            "subtract": lambda: second - top,
            "multiply": lambda: second * top,
            "divide": lambda: second // top,
            "mod": lambda: second % top,
            "greater": lambda: int(second > top),
        }
        stack.append(operations[command]())
    elif command == "not" and stack:
        stack[-1] = int(stack[-1] == 0)
    elif command == "duplicate" and stack:
        stack.append(stack[-1])
    elif command == "roll" and len(stack) >= 2:
        rolls = stack.pop()
        depth = stack.pop()
        if depth <= 0 or depth > len(stack):
            return
        rolls %= depth
        if rolls:
            stack[-depth:] = stack[-rolls:] + stack[-depth:-rolls]
    elif command == "in-number":
        value = input_stream.read_number()
        if value is not None:
            stack.append(value)
    elif command == "in-char":
        value = input_stream.read_char()
        if value is not None:
            stack.append(value)
    elif command == "out-number" and stack:
        output.append(str(stack.pop()))
    elif command == "out-char" and stack:
        value = stack.pop() % 0x110000
        output.append("�" if 0xD800 <= value <= 0xDFFF else chr(value))


def _apply_direction_command(command: str, stack: list[int], dp: int, cc: int) -> tuple[int, int]:
    if command == "pointer" and stack:
        dp = (dp + stack.pop()) % 4
    elif command == "switch" and stack:
        cc = (cc + stack.pop()) % 2
    return dp, cc


class _InputStream:
    def __init__(self, data: str) -> None:
        self.data = data
        self.position = 0

    def read_number(self) -> int | None:
        match = re.match(r"\s*([+-]?\d+)", self.data[self.position :])
        if match is None:
            return None
        self.position += match.end()
        return int(match.group(1))

    def read_char(self) -> int | None:
        if self.position >= len(self.data):
            return None
        value = ord(self.data[self.position])
        self.position += 1
        return value


def _piet_result(
    input_path: Path,
    image_size: tuple[int, int],
    codel_size: int,
    codel_width: int,
    codel_height: int,
    steps: int,
    halted: bool,
    halt_reason: str,
    stdout: str,
    stack: list[int],
    unknown_codels: int,
    trace_steps: list[PietTraceStep],
    trace_image_path: Path | None,
    path: list[tuple[int, int]],
) -> PietResult:
    output_paths: list[str] = []
    if trace_image_path is not None:
        _draw_trace_image(input_path, trace_image_path, codel_size, path)
        output_paths.append(str(trace_image_path))
    return PietResult(
        operation="image.npiet.run",
        input_path=str(input_path),
        output_path=str(trace_image_path) if trace_image_path else None,
        output_paths=output_paths,
        count=steps,
        width=image_size[0],
        height=image_size[1],
        codel_size=codel_size,
        codel_width=codel_width,
        codel_height=codel_height,
        steps=steps,
        halted=halted,
        halt_reason=halt_reason,
        stdout=stdout,
        stdout_hex=stdout.encode("utf-8").hex(),
        stack=stack.copy(),
        unknown_codels=unknown_codels,
        trace=[asdict(item) for item in trace_steps] if trace_steps else None,
    )


def _draw_trace_image(
    input_path: Path, output_path: Path, codel_size: int, path: list[tuple[int, int]]
) -> None:
    with Image.open(input_path) as source:
        image = source.convert("RGB")
    draw = ImageDraw.Draw(image)
    centers = [
        (x * codel_size + codel_size // 2, y * codel_size + codel_size // 2) for x, y in path
    ]
    if len(centers) > 1:
        draw.line(centers, fill=(255, 128, 0), width=max(1, codel_size // 3))
    for center in centers[:1]:
        radius = max(1, codel_size // 3)
        draw.ellipse(
            (center[0] - radius, center[1] - radius, center[0] + radius, center[1] + radius),
            fill=(0, 0, 0),
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)


def _nearest_palette_index(color: tuple[int, int, int]) -> int:
    palette = np.asarray((*PIET_PALETTE, WHITE, BLACK), dtype=np.int32)
    value = np.asarray(color, dtype=np.int32)
    index = int(np.argmin(np.sum((palette - value) ** 2, axis=1)))
    if index == 18:
        return -1
    if index == 19:
        return -2
    return index


def _inside(codels: np.ndarray, position: tuple[int, int]) -> bool:
    return 0 <= position[0] < codels.shape[1] and 0 <= position[1] < codels.shape[0]
