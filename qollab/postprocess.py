"""Portable, measured-phase-only Shor postprocessing. No SDK dependency."""
from __future__ import annotations
import math


def convergent_denominators(numerator: int, denominator: int):
    """Continued fractions using integer arithmetic only."""
    old_q, q = 1, 0
    while denominator:
        a, remainder = divmod(numerator, denominator)
        old_q, q = q, a * q + old_q
        yield q
        numerator, denominator = denominator, remainder


def factors_from_measurements(modulus: int, base: int, phase_bits: int, weights: dict[int, float]) -> tuple[int, int] | None:
    """Try denominators actually supported by measurements, including their LCM.

    This does not search r=1,2,... or substitute a known factor/order. LCMs are
    bounded by N and by 128 accumulated candidates to keep work predictable.
    """
    candidates = {1}
    for outcome, weight in sorted(weights.items(), key=lambda item: -item[1]):
        if outcome == 0 or weight <= 0:
            continue
        # A convergent is useful only at phase-estimation resolution; this avoids
        # combining arbitrary early denominators such as 1 or 2 from noisy tails.
        for denominator in convergent_denominators(outcome, 1 << phase_bits):
            if not 1 < denominator < modulus:
                continue
            numerator = (outcome * denominator + (1 << (phase_bits - 1))) >> phase_bits
            if abs(outcome * denominator - numerator * (1 << phase_bits)) > denominator:
                continue
            additions = {denominator}
            additions.update(math.lcm(denominator, old) for old in tuple(candidates))
            for order in sorted(additions):
                if order >= modulus:
                    continue
                if len(candidates) < 128:
                    candidates.add(order)
                if order % 2 or pow(base, order, modulus) != 1:
                    continue
                midpoint = pow(base, order // 2, modulus)
                for factor in (math.gcd(midpoint - 1, modulus), math.gcd(midpoint + 1, modulus)):
                    if 1 < factor < modulus:
                        other = modulus // factor
                        answer = (min(factor, other), max(factor, other))
                        assert answer[0] * answer[1] == modulus
                        return answer
    return None
