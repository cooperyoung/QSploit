"""Polynomial Fourier arithmetic (Beauregard modular reduction).

Registers are little endian. Modular semantics hold on 0 <= x < modulus;
the construction is unitary elsewhere but does not promise identity there.
No truth tables, dense unitaries, factors or precomputed orders are used.
"""
from __future__ import annotations

import math


def fourier_add_constant(circuit, register, value: int, controls=()) -> None:
    """Add value modulo 2**len(register), to a full-QFT-encoded register."""
    width = len(register)
    for j, qubit in enumerate(register):
        numerator = (value * (1 << j)) % (1 << width)
        if numerator:
            angle = 2 * math.pi * numerator / (1 << width)
            if not controls:
                circuit.p(angle, qubit)
            elif len(controls) == 1:
                circuit.cp(angle, controls[0], qubit)
            else:
                circuit.mcp(angle, list(controls), qubit)


def controlled_add_mod_n(circuit, register, flag, value: int, modulus: int, controls=()) -> None:
    """In Fourier basis, add value modulo N when all controls are one.

    Requires N < 2**(width-1), input b < N, and flag=0. Restores flag=0.
    The extra most-significant accumulator qubit detects subtraction underflow.
    """
    from qiskit.circuit.library import QFTGate
    if not 1 < modulus < 1 << (len(register) - 1):
        raise ValueError("Accumulator needs an extra comparison bit")
    value %= modulus
    if not value:
        return
    qft = QFTGate(len(register))
    fourier_add_constant(circuit, register, value, controls)
    fourier_add_constant(circuit, register, -modulus)
    circuit.append(qft.inverse(), register)
    circuit.cx(register[-1], flag)
    circuit.append(qft, register)
    fourier_add_constant(circuit, register, modulus, [flag])
    fourier_add_constant(circuit, register, -value, controls)
    circuit.append(qft.inverse(), register)
    circuit.x(register[-1])
    circuit.cx(register[-1], flag)
    circuit.x(register[-1])
    circuit.append(qft, register)
    fourier_add_constant(circuit, register, value, controls)


def _multiply_accumulate(width: int, value: int, modulus: int):
    from qiskit import QuantumCircuit
    from qiskit.circuit.library import QFTGate
    circuit = QuantumCircuit(2 * width + 3, name=f"accumulate_{value}_mod_{modulus}")
    control = circuit.qubits[0]
    work = circuit.qubits[1:1 + width]
    accumulator = circuit.qubits[1 + width:-1]
    flag = circuit.qubits[-1]
    circuit.append(QFTGate(width + 1), accumulator)
    for j, qubit in enumerate(work):
        controlled_add_mod_n(circuit, accumulator, flag, value * (1 << j), modulus, [control, qubit])
    circuit.append(QFTGate(width + 1).inverse(), accumulator)
    return circuit


def controlled_multiply_mod_n(value: int, modulus: int):
    """Return gate with [control, work(n), accumulator(n+1), flag] wires.

    Given zero scratch: |c,x,0,0> -> |c,(a*x mod N if c else x),0,0>.
    Clean via a controlled swap followed by inverse accumulation using a^-1.
    """
    from qiskit import QuantumCircuit
    width = modulus.bit_length()
    if modulus <= 2 or math.gcd(value, modulus) != 1:
        raise ValueError("Multiplier must be invertible modulo N")
    value %= modulus
    circuit = QuantumCircuit(2 * width + 3, name=f"multiply_{value}_mod_{modulus}")
    if value == 1:
        return circuit.to_gate()
    circuit.compose(_multiply_accumulate(width, value, modulus), inplace=True)
    for j in range(width):
        circuit.cswap(0, 1 + j, 1 + width + j)
    circuit.compose(_multiply_accumulate(width, pow(value, -1, modulus), modulus).inverse(), inplace=True)
    return circuit.to_gate()


def order_finding_circuit(modulus: int, base: int = 2):
    """Coherent QPE using 2n phase bits and n+n+1+1 work/scratch bits."""
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
    from qiskit.circuit.library import QFTGate
    if modulus <= 2 or not 1 < base < modulus or math.gcd(base, modulus) != 1:
        raise ValueError("Order finding requires an invertible base between 1 and N")
    width = modulus.bit_length()
    phase = QuantumRegister(2 * width, "phase")
    work = QuantumRegister(width, "work")
    accumulator = QuantumRegister(width + 1, "acc")
    flag = QuantumRegister(1, "flag")
    measured = ClassicalRegister(2 * width, "measured_phase")
    circuit = QuantumCircuit(phase, work, accumulator, flag, measured, name=f"order_N{modulus}_a{base}")
    circuit.metadata = {"modulus": modulus, "base": base, "phase_bits": 2 * width, "construction": "fourier_modular_arithmetic"}
    circuit.h(phase)
    circuit.x(work[0])
    power = base
    for qubit in phase:
        if power != 1:
            circuit.append(controlled_multiply_mod_n(power, modulus), [qubit, *work, *accumulator, *flag])
        power = power * power % modulus
    circuit.append(QFTGate(2 * width).inverse(), phase)
    circuit.measure(phase, measured)
    return circuit
