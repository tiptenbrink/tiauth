from typing import Self
from bisect import bisect
from time import time

class Expiry:
    v: int | None

    @classmethod
    def inf(cls):
        i = Expiry(-1)
        i.v = None
        return i

    def __init__(self, v: int):
        self.v = v

    def __lt__(self, other: Self):
        if self.v is None:
            return False
        if other.v is None:
            return True
        
        return self.v.__lt__(other.v)
    
    def __str__(self):
        return f"{str(self.v)}" if self.v is not None else "inf"

RANGE_SIZE = 1

class Range:
    l: None | list[int]
    min: int
    max: int
    expires: Expiry

    def __init__(self, min: int) -> None:
        self.l = []
        self.min = min
        self.max = min + (RANGE_SIZE-1)
        self.expires = Expiry.inf()

    def __str__(self):
        l_str = "full" if self.l is None else str(self.l)
        exp_str = f"exp={self.expires}"
        return f"[{self.min},{self.max};{l_str};{exp_str}]"
    
class MergeRange:
    ranges: list[Range]

    def __init__(self) -> None:
        self.ranges = [Range(0)]

    @classmethod
    def with_ranges(cls, ranges: list[Range]) -> Self:
        new_m_range = cls()
        new_m_range.ranges = ranges
        return new_m_range

    def __str__(self):
        return f"MergeRange:\n{",".join(map(str, self.ranges))}"

def add_num(m_range: MergeRange, num: int, expires: Expiry):
    n_i = bisect(m_range.ranges, num, key=lambda r: r.min)

    target_range = m_range.ranges[n_i-1]
    
    if n_i == len(m_range.ranges):
        while True:
            if num > target_range.max:
                target_range = Range(target_range.max+1)
                m_range.ranges.append(target_range)
            else:
                break

        n_i = len(m_range.ranges)
        next = None
    else:
        next = m_range.ranges[n_i]

    target_i = n_i-1
    print(f"target range {n_i}: {target_range}")
    
    
    if target_range.l is None or num in target_range.l:
        return True
    
    if target_i != 0:
        prev = m_range.ranges[target_i-1]
    else:
        prev = None
    
    if len(target_range.l)+1 == RANGE_SIZE:
        target_range.l = None

        remove_range = False
        remove_next = False

        if prev is not None and prev.l is None and next is not None and next.l is None:
            remove_range = True
            remove_next = True
            prev.max = next.max
        elif prev is not None and prev.l is None:
            remove_range = True
            prev.max = target_range.max
        elif next is not None and next.l is None:
            remove_next = True
            target_range.max = next.max

        # it's important this one is first so that the other one is not affected
        if remove_next:
            m_range.ranges.pop(n_i)
        if remove_range:
            m_range.ranges.pop(target_i)
        

    exp_i = bisect(m_range.ranges, expires, key=lambda r: r.expires)
    print(f"exp_i {exp_i}")

    for r in m_range.ranges[exp_i:n_i-1]:
        r.expires = expires

rngs = []
for i in range(10):
    r = Range(i*RANGE_SIZE)
    if i < 7:
        r.expires = Expiry(i*300)
    rngs.append(r)

def check_expired(m_range: MergeRange, time: int) -> MergeRange:
    exp_i = bisect(m_range.ranges, Expiry(time), key=lambda r: r.expires)
    first_min = m_range.ranges[0].min
    last_max = m_range.ranges[exp_i-1].max
    new_range = Range(first_min)
    new_range.max = last_max
    new_range.l = None
    new_range.expires = Expiry(0)
    return MergeRange.with_ranges([new_range] + m_range.ranges[exp_i:])

r = MergeRange()
r.ranges = rngs
print(r)
add_num(r, 5, Expiry(400))
print(r)
check_expired(r, 2000)
print(r)
# add_num(r, 23, Expiry(200))
# print(r)
# add_num(r, 4, Expiry(400))
# print(r)
# add_num(r, 8, Expiry(300))
# print(r)
# add_num(r, 7, Expiry(300))
# print(r)
# add_num(r, 6, Expiry(900))
# print(r)
