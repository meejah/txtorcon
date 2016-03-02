from txtorcon.util import process_from_address

import pytest


class FakeState:
    tor_pid = 0

@pytest.fixture
def fakestate():
    return FakeState()

def test_none(fakestate):
    "Ensure we do something useful on a None address."
    assert process_from_address(None, 80, fakestate) is None

def test_internal(fakestate):
    "Look up the (Tor_internal) PID."
    pfa = process_from_address('(Tor_internal)', 80, fakestate)
    # Depends on whether you have psutil installed or not, and on
    # whether your system always has a PID 0 process...
    assert pfa == fakestate.tor_pid

def test_internal_no_state(fakestate):
    "Look up the (Tor_internal) PID."
    pfa = process_from_address('(Tor_internal)', 80)
    # Depends on whether you have psutil installed or not, and on
    # whether your system always has a PID 0 process...
    assert pfa is None
