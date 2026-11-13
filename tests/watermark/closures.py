SHARED = ('shared', 'shared', b'bytes', 3.14159, 1+2j, 2**90, None)
def calculate(value):
    # Keep code, branch/exception-table, Unicode and nested reference semantics.
    values = ('shared', '水印', b'bytes', 1.5, 1+2j, 2**90)
    try:
        if value < 0:
            return -1
        return value * 7 if values[0] == SHARED[0] else 0
    except TypeError:
        return -2
def outer(number):
    def inner(delta):
        return number + delta
    return inner
