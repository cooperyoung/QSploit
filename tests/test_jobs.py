"""Worker trust boundary: valid factors alone do not establish claimed provenance."""
from dataclasses import replace

import pytest

from qsploit.jobs import verify_recovery
from qsploit.models import ExecutionOptions, Measurement, QSploitError, Recovery, RSAFactors, RSAProblem

PROBLEM = RSAProblem(15)
FACTORS = RSAFactors(3,5)


def evidence(**updates):
    baseline = Measurement({0:128.0,64:128.0},'counts',256,'aer','aer_simulator_matrix_product_state',None,'a'*64,18,100,80)
    return replace(baseline,**updates)


def quantum_result(measurements=None,**updates):
    baseline = Recovery(FACTORS,'quantum_order_finding','aer','aer_simulator_matrix_product_state',(evidence(),) if measurements is None else measurements)
    return replace(baseline,**updates)


def test_verified_fixture_and_actual_quantum_provenance_are_separate():
    verify_recovery(PROBLEM,Recovery(FACTORS,'fixture_lookup','none',None,()),ExecutionOptions('fixture'))
    verify_recovery(PROBLEM,quantum_result(),ExecutionOptions('aer',shots=256))
    verify_recovery(PROBLEM,Recovery(FACTORS,'classical_precheck','none',None,()),ExecutionOptions('aer'))


@pytest.mark.parametrize('result,backend',[
    (Recovery(FACTORS,'fixture_lookup','none',None,()),'aer'),
    (Recovery(FACTORS,'fixture_lookup','aer',None,()),'fixture'),
    (Recovery(FACTORS,'fixture_lookup','none',None,(evidence(),)),'fixture'),
    (Recovery(FACTORS,'classical_precheck','none',None,()),'fixture'),
    (Recovery(FACTORS,'classical_precheck','aer',None,()),'aer'),
    (quantum_result(measurements=()),'aer'),
    (quantum_result(execution='ionq_simulator'),'aer'),
    (quantum_result(target='a different target'),'aer'),
    (quantum_result(method='fabricated success'),'aer'),
])
def test_inconsistent_method_or_execution_cannot_pass_boundary(result,backend):
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,result,ExecutionOptions(backend))
    assert error.value.code == 'INVALID_PROVENANCE'


@pytest.mark.parametrize('measurement',[
    evidence(weights={0:float('nan')}),
    evidence(weights={0:float('inf')}),
    evidence(weights={0:-256}),
    evidence(weights={256:256}),
    evidence(weights={-1:256}),
    evidence(weights={0:True}),
    evidence(weights={0:255}),
    evidence(weights={0:255.5,64:.5}),
    evidence(weights={0:.5},kind='probabilities',actual_shots=None),
    evidence(weights={0:1},kind='probabilities',actual_shots=256),
    evidence(execution='ionq_qpu'),
    evidence(circuit_sha256=''),
    evidence(qubits=7),
    evidence(compiled_ops=0),
    evidence(compiled_depth=0),
])
def test_tampered_measurements_fail_even_when_factors_are_valid(measurement):
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,quantum_result((measurement,)),ExecutionOptions('aer'))
    assert error.value.code in {'INVALID_MEASUREMENT','INVALID_PROVENANCE'}


@pytest.mark.parametrize('measurement',[
    evidence(qubits=23),
    evidence(compiled_ops=250001),
    evidence(weights={0:1025},actual_shots=1025),
])
def test_worker_cannot_exceed_requested_budgets(measurement):
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,quantum_result((measurement,)),ExecutionOptions('aer',shots=1024))
    assert error.value.code == 'INVALID_PROVENANCE'


def test_worker_cannot_return_more_circuits_than_attempt_budget():
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,quantum_result((evidence(),evidence())),ExecutionOptions('aer',max_attempts=1))
    assert error.value.code == 'INVALID_PROVENANCE'


def test_ionq_requires_provider_job_and_preserves_probability_provenance():
    measurement = evidence(weights={0:.5,64:.5},kind='probabilities',actual_shots=None,execution='ionq_simulator',target='ionq_simulator',provider_job_id='test-provider-job')
    result = quantum_result((measurement,),execution='ionq_simulator',target='ionq_simulator')
    options = ExecutionOptions('ionq_simulator',target='ionq_simulator')
    verify_recovery(PROBLEM,result,options)
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,replace(result,measurements=(replace(measurement,provider_job_id=None),)),options)
    assert error.value.code == 'INVALID_PROVENANCE'


def test_bad_factor_pair_is_reverified_in_parent():
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,quantum_result(factors=RSAFactors(3,7)),ExecutionOptions('aer'))
    assert error.value.code == 'INVALID_FACTOR_PAIR'


@pytest.mark.parametrize('measurement',[
    evidence(qubits=float('nan')),
    evidence(qubits=18.5),
    evidence(compiled_ops=float('nan')),
    evidence(compiled_ops=100.5),
    evidence(compiled_depth=float('inf')),
    evidence(compiled_depth=True),
    evidence(circuit_sha256='z'*64),
])
def test_resource_metadata_and_hash_shape_are_verified(measurement):
    with pytest.raises(QSploitError) as error:
        verify_recovery(PROBLEM,quantum_result((measurement,)),ExecutionOptions('aer'))
    assert error.value.code == 'INVALID_PROVENANCE'
