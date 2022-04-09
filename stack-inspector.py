import gdb
from collections import OrderedDict, namedtuple

## frame unwinder is better for this?
##   https://sourceware.org/gdb/onlinedocs/gdb/Unwinding-Frames-in-Python.html#Unwinding-Frames-in-Python

ANSI_BOLD = "\x1b[1m"
ANSI_GREEN = "\x1b[32m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_RESET = "\x1b[0m"


Symbol = namedtuple('Symbol', ['size', 'typename'])


def analyze_frame(frame_nr, frame):
    info = frame.find_sal()

    if info.symtab:
        print("  {bold}#{frame_nr:<3}{reset} "
              "{green}{function}{reset}"
              " @ "
              "{filename}:{line}".format(
                frame_nr=frame_nr,
                filename=info.symtab.filename,
                line=info.line,
                function=frame.function().name,
                bold=ANSI_BOLD,
                green=ANSI_GREEN,
                reset=ANSI_RESET))
    else:
        print("  {bold}#{frame_nr:<3}{reset} Could not retrieve frame information".format(
            frame_nr=frame_nr,
            bold=ANSI_BOLD,
            green=ANSI_GREEN,
            reset=ANSI_RESET))

    # $pc: program counter register
    # $sp: stack pointer
    # $fp: pointer to current stack frame
    print("{space}pc: 0x{pc:x}\n{space}sp: {sp}\n{space}fp: {fp}".format(
            pc=frame.pc(),
            sp=frame.read_register("sp"),
            fp=frame.read_register("fp"),
            space="           "
            ))

    if not info.symtab:
        return

    try:
        block = frame.block()
    except RuntimeError:
        print("Could not retrieve block information")
        return

    symbols = {}
    while block:
        if not (block.is_global or block.is_static):
            for symbol in block:
                # We only show symbols which are on the call stack
                # - function arguments
                # - local variables (which need frame information, no static variables)
                if symbol.is_argument or \
                        (symbol.is_variable and symbol.addr_class != gdb.SYMBOL_LOC_STATIC):
                    if symbol.name not in symbols:
                        symbols[symbol.name] = Symbol(symbol.type.sizeof, symbol.type)

        block = block.superblock

    symbols = OrderedDict(sorted(symbols.items(),
                                 key=lambda s: s[1].size,
                                 reverse=True))

    for name, (size, typename) in symbols.items():
        print("    {bold}{size:>14,}{reset}   {name} ({cyan}{typename}{reset})".format(
                size=size,
                name=name,
                typename=typename,
                cyan=ANSI_CYAN,
                magenta=ANSI_MAGENTA,
                bold=ANSI_BOLD,
                reset=ANSI_RESET
                ))

    print()


class StackVisualizer(gdb.Command):
    """Inspect the stack for large objects"""

    def __init__(self):
        super(StackVisualizer, self).__init__("stack-inspector", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            print("[stack-inspector] could not retrieve frame information (no stack).")
            return

        backtrace = []

        fstart = 0
        fend = 999999
        argv = gdb.string_to_argv(arg)
        if ( len(argv) > 1 ):
            fstart = int(gdb.parse_and_eval(argv[0]))
            fend = fstart + int(gdb.parse_and_eval(argv[1])) - 1
        elif ( len(argv) > 0 ):
            fend = int(gdb.parse_and_eval(argv[0])) - 1

        while frame:
            backtrace.append(frame)
            frame = frame.older()

        print()
        for frame_nr, frame in enumerate(backtrace):
            if frame_nr >= fstart:
                analyze_frame(frame_nr, frame)
            if frame_nr >= fend:
                break

StackVisualizer()
