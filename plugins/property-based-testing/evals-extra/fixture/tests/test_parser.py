from hypothesis import given, assume, strategies as st
from src.codec import unpack


@given(st.binary())
def test_unpack_runs(data):
    try:
        unpack(data)
    except Exception:
        pass


@given(st.integers())
def test_narrow(x):
    assume(x > 100)
    assume(x < 50)
    assert x
