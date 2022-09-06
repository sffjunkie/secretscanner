from collections import Counter
from math import log


def shannon(string: str):
    counts = Counter(string)
    frequencies = ((i / len(string)) for i in counts.values())
    return -sum(f * log(f, 2) for f in frequencies)
