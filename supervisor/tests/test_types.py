import dataclasses
import pytest
from dashield.domain.types import Verdict, FeatureVector, TelemetryRecord


def test_verdict_numeric_values() -> None:
    """Verifica che i valori dell'enum e la mappatura bidirezionale coincidano."""
    # Verifica l'attributo scalare .value
    assert Verdict.BENIGN.value == 0
    assert Verdict.ATTACK.value == 1
    assert Verdict.AMBIGUOUS.value == 2

    # Verifica la costruzione inversa da intero a Enum (fondamentale per la seriale)
    assert Verdict(0) == Verdict.BENIGN
    assert Verdict(1) == Verdict.ATTACK
    assert Verdict(2) == Verdict.AMBIGUOUS

    # Verifica che sia un'istanza di int a runtime
    assert isinstance(Verdict.BENIGN, int)


def test_feature_vector_immutability() -> None:
    """Verifica che FeatureVector sia immutabile (frozen) e supporti to_tuple."""
    vec = FeatureVector(
        norm_length=0.42,
        delta_time_us=150.0,
        protocol_flags=0.0,
        byte_variance=25.5,
    )

    # Verifica conversione in tupla ordinata
    assert vec.to_tuple() == (0.42, 150.0, 0.0, 25.5)

    # Verifica che tentare di modificare un campo sollevi FrozenInstanceError
    with pytest.raises(dataclasses.FrozenInstanceError):
        vec.norm_length = 0.99  # type: ignore[misc]


def test_telemetry_record_structure_and_integrity() -> None:
    """Verifica la corretta aggregazione del record di telemetria e la sua immutabilità."""
    features = FeatureVector(
        norm_length=0.1,
        delta_time_us=45.0,
        protocol_flags=1.0,
        byte_variance=180.2,
    )

    record = TelemetryRecord(
        node_id=101,
        rule_id=14,
        sequence_id=1001,
        verdict=Verdict.ATTACK,
        split_feature=3,
        features=features,
        crc32=0xDEADBEEF,
    )

    assert record.node_id == 101
    assert record.verdict == Verdict.ATTACK
    assert record.features.byte_variance == 180.2

    # Verifica immutabilità a livello root
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.verdict = Verdict.BENIGN  # type: ignore[misc]
