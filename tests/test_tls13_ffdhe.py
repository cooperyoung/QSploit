"""Finite-field TLS 1.3 share encoding and negotiation fail-closed checks."""
from dataclasses import replace
from pathlib import Path

import pytest

from qsploit.groups import FFDHE2048_P
from qsploit.models import QSploitError, TCPConnection
from qsploit.pcap import read_connections
from qsploit.tls import _hello, parse_tls, problem_for

ROOT = Path(__file__).parents[1]


@pytest.fixture(params=["tls13-dhe-aes128", "tls13-dhe-aes256"])
def ff_session(request):
    data = (ROOT / "tests/fixtures" / (request.param + ".pcap")).read_bytes()
    return parse_tls(read_connections(data).connections[0])


def mutate_hello(session, direction, update):
    records = list(session.records)
    index = next(i for i, record in enumerate(records) if record.direction == direction and record.content_type == 22)
    wire = records[index].fragment
    hello = _hello(wire, direction == "c2s")
    extensions = dict(hello["ext"])
    old_length = sum(4 + len(value) for value in extensions.values()) + 2
    update(extensions)
    encoded = b"".join(kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value for kind, value in extensions.items())
    body = wire[4:-old_length] + len(encoded).to_bytes(2, "big") + encoded
    records[index] = replace(records[index], fragment=wire[:1] + len(body).to_bytes(3, "big") + body)

    def stream(side):
        return b"".join(bytes([r.content_type]) + r.version.to_bytes(2, "big") + len(r.fragment).to_bytes(2, "big") + r.fragment for r in records if r.direction == side)

    return parse_tls(TCPConnection("ffdhe-wire-test", session.client, session.server,
                                  stream("c2s"), stream("s2c"), True, True, (), ()))


def set_share(extensions, direction, public, group=256):
    encoded = group.to_bytes(2, "big") + len(public).to_bytes(2, "big") + public
    extensions[51] = len(encoded).to_bytes(2, "big") + encoded if direction == "c2s" else encoded


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
@pytest.mark.parametrize("size", [255, 257])
def test_modulus_width_is_required_even_for_identical_valid_integer(direction, size, ff_session):
    changed = mutate_hello(ff_session, direction, lambda ext: set_share(ext, direction, (2).to_bytes(size, "big")))
    assert "INVALID_DH_PUBLIC" in changed.blockers
    with pytest.raises(QSploitError):
        problem_for(changed)


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
def test_valid_small_share_with_full_leading_zero_padding_is_accepted(direction, ff_session):
    changed = mutate_hello(ff_session, direction, lambda ext: set_share(ext, direction, (2).to_bytes(256, "big")))
    assert not changed.blockers
    assert changed.dhe.client_public == 2 if direction == "c2s" else changed.dhe.server_public == 2
    assert problem_for(changed).kind == "ff_dlog"


@pytest.mark.parametrize("direction", ["c2s", "s2c"])
@pytest.mark.parametrize("public", [0, 1, FFDHE2048_P - 1, FFDHE2048_P, FFDHE2048_P + 1, FFDHE2048_P - 2])
def test_out_of_range_or_outside_prime_subgroup_shares_rejected(direction, public, ff_session):
    changed = mutate_hello(ff_session, direction, lambda ext: set_share(ext, direction, public.to_bytes(256, "big")))
    assert "INVALID_DH_PUBLIC" in changed.blockers


@pytest.mark.parametrize("variant", ["unoffered_group", "missing_key_share", "wrong_key_share_group", "duplicate_key_share"])
def test_selected_group_must_be_offered_with_one_matching_share(variant, ff_session):
    def update(ext):
        if variant == "unoffered_group":
            ext[10] = b"\x00\x02\x00\x17"
        elif variant == "missing_key_share":
            ext[51] = b"\x00\x00"
        elif variant == "wrong_key_share_group":
            set_share(ext, "c2s", (2).to_bytes(256, "big"), group=257)
        else:
            share = ext[51][2:]
            ext[51] = (2 * len(share)).to_bytes(2, "big") + share + share
    changed = mutate_hello(ff_session, "c2s", update)
    assert "INVALID_TLS" in changed.blockers


def test_other_named_ffdhe_groups_remain_unsupported(ff_session):
    changed = mutate_hello(ff_session, "s2c", lambda ext: set_share(ext, "s2c", (2).to_bytes(384, "big"), group=257))
    assert changed.selected_group == 257 and changed.kex == "dhe"
    assert "UNSUPPORTED_GROUP" in changed.blockers
