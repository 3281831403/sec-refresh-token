"""Fixed edge-case tests for the refresh-token bugfix exercise.

Five scenarios: a healthy renewal, revocation of a family on replay, a client
mismatch, an expired token, and batch processing that matches the same
requests handled one by one.  These tests are immutable: only
``token/refresh.py`` may be changed.
"""

import copy

from token.refresh import (
    MIN_ENTROPY_BYTES,
    bind_ok,
    check_reuse,
    issue_family,
    refresh_batch,
    rotate,
    ttl_ok,
)

NOW = 1_700_000_000_000  # milliseconds
ENTROPY = bytes(range(MIN_ENTROPY_BYTES))
SECRET = b"k" * 32


def _store():
    return {"secret": SECRET, "seq": 0, "families": {}, "tokens": {}}


def _policy(**overrides):
    policy = {
        "reuse_detection": True,
        "client_binding": True,
        "absolute_ttl_seconds": 3600,
        "idle_ttl_seconds": 300,
    }
    policy.update(overrides)
    return policy


def _clone(store):
    return copy.deepcopy(store)


def test_normal_renewal_succeeds():
    policy = _policy()
    store = _store()
    issued = issue_family(store, "carol", "ios", ENTROPY, NOW)

    renewed = rotate(store, issued, NOW + 60_000, policy)

    assert renewed["ok"] is True
    assert renewed["reason"] == "rotated"
    assert renewed["family_id"] == issued["family_id"]
    new = renewed["token"]
    assert new["user"] == "carol"
    assert new["client"] == "ios"
    assert new["previous"] == issued["token"]
    assert bind_ok(new, "ios") is True
    assert ttl_ok(new, NOW + 60_000, policy) is True
    assert check_reuse(store, new)["reuse"] is False
    assert check_reuse(store, new)["reason"] == "ok"
    assert store["tokens"][issued["token"]]["used_at"] == NOW + 60_000


def test_replayed_token_is_rejected_and_whole_family_revoked():
    policy = _policy()
    store = _store()
    issued = issue_family(store, "dave", "web", ENTROPY, NOW)
    renewed = rotate(store, issued, NOW + 1000, policy)["token"]

    replay = rotate(store, issued, NOW + 2000, policy)

    assert replay["ok"] is False
    assert replay["reason"] == "reuse"
    assert replay["token"] is None
    assert store["families"][issued["family_id"]]["revoked_at"] == NOW + 1000
    assert check_reuse(store, renewed)["reuse"] is True
    assert check_reuse(store, renewed)["reason"] == "revoked"
    assert check_reuse(store, renewed)["revoked"] == 0
    assert rotate(store, renewed, NOW + 3000, policy)["reason"] == "revoked"


def test_client_mismatch_is_rejected_without_state_change():
    policy = _policy()
    store = _store()
    issued = issue_family(store, "erin", "web", ENTROPY, NOW)

    assert bind_ok(issued, "web") is True
    assert bind_ok(issued, "web-mobile") is False

    rejected = refresh_batch(
        [{"store": store, "token": issued, "client": "web-mobile"}],
        policy,
        NOW + 1000,
    )["results"][0]
    assert rejected["ok"] is False
    assert rejected["reason"] == "client_mismatch"
    assert rejected["family_id"] == issued["family_id"]
    assert store["tokens"][issued["token"]]["used_at"] is None
    assert store["families"][issued["family_id"]]["revoked_at"] is None

    accepted = refresh_batch(
        [{"store": store, "token": issued, "client": "web"}],
        policy,
        NOW + 1000,
    )["results"][0]
    assert accepted["ok"] is True
    assert bind_ok(accepted["token"], "web") is True


def test_expired_token_is_rejected_at_the_boundary():
    policy = _policy(absolute_ttl_seconds=600, idle_ttl_seconds=120)
    store = _store()
    issued = issue_family(store, "frank", "web", ENTROPY, NOW)

    assert ttl_ok(issued, NOW + 119_999, policy) is True
    assert ttl_ok(issued, NOW + 120_000, policy) is False

    stalled = rotate(store, issued, NOW + 120_000, policy)
    assert stalled["ok"] is False
    assert stalled["reason"] == "expired"
    assert store["tokens"][issued["token"]]["used_at"] is None

    batched = refresh_batch(
        [{"store": store, "token": issued, "client": "web"}],
        policy,
        NOW + 500_000,
    )["results"][0]
    assert batched["reason"] == "expired"


def test_two_batches_match_individual_processing():
    policy = _policy()
    base_a = _store()
    base_b = _store()
    issue_family(base_a, "alice", "web", ENTROPY, NOW)
    issue_family(base_b, "bob", "web", ENTROPY, NOW)

    batch_a = _clone(base_a)
    batch_b = _clone(base_b)
    single_a = _clone(base_a)
    single_b = _clone(base_b)

    def request(store, user):
        record = next(
            item for item in store["tokens"].values() if item["user"] == user
        )
        return {"store": store, "token": record, "client": "web"}

    batched = refresh_batch(
        [request(batch_a, "alice"), request(batch_b, "bob")],
        policy,
        NOW + 5000,
    )["results"]
    singles = [
        refresh_batch([request(single_a, "alice")], policy, NOW + 5000)[
            "results"
        ][0],
        refresh_batch([request(single_b, "bob")], policy, NOW + 5000)[
            "results"
        ][0],
    ]

    assert [result["ok"] for result in batched] == [
        result["ok"] for result in singles
    ]
    assert [result["reason"] for result in batched] == [
        result["reason"] for result in singles
    ]
    assert [result["family_id"] for result in batched] == [
        result["family_id"] for result in singles
    ]
    assert [result["token"]["token"] for result in batched] == [
        result["token"]["token"] for result in singles
    ]
    assert batch_a["families"] == single_a["families"]
    assert batch_b["families"] == single_b["families"]
    assert batch_a["tokens"] == single_a["tokens"]
    assert batch_b["tokens"] == single_b["tokens"]