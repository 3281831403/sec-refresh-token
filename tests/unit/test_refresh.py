"""Fixed contract tests for the refresh-token bugfix exercise.

One test per documented defect, in the documented order.  These tests are
immutable: only ``token/refresh.py`` may be changed.
"""

from token.refresh import (
    MAX_ABSOLUTE_TTL_SECONDS,
    MIN_ENTROPY_BYTES,
    POLICY_ISSUE_ABSOLUTE,
    POLICY_ISSUE_BINDING,
    POLICY_ISSUE_ORDER,
    POLICY_ISSUE_REUSE,
    TOKEN_LENGTH,
    bind_ok,
    check_reuse,
    issue_family,
    refresh_batch,
    revoke_family,
    rotate,
    ttl_ok,
    validate_policy,
)

NOW = 1_700_000_000_000  # milliseconds
ENTROPY = bytes(range(MIN_ENTROPY_BYTES))
SECRET = b"s" * 32


def _store(secret=SECRET):
    return {"secret": secret, "seq": 0, "families": {}, "tokens": {}}


def _policy(**overrides):
    policy = {
        "reuse_detection": True,
        "client_binding": True,
        "absolute_ttl_seconds": 3600,
        "idle_ttl_seconds": 300,
    }
    policy.update(overrides)
    return policy


def test_defect_01_rotation_marks_the_presented_token_as_used():
    store = _store()
    issued = issue_family(store, "alice", "web", ENTROPY, NOW)

    rotated = rotate(store, issued, NOW + 10, _policy())

    assert rotated["ok"] is True
    assert rotated["reason"] == "rotated"
    assert rotated["old_token"] == issued["token"]
    assert rotated["token"]["token"] != issued["token"]
    assert len(store["tokens"]) == 2
    assert store["tokens"][issued["token"]]["used_at"] == NOW + 10
    assert rotated["token"]["used_at"] is None

    replay = rotate(store, issued, NOW + 10, _policy())
    assert replay["ok"] is False
    assert replay["reason"] == "reuse"


def test_defect_02_reuse_detection_revokes_the_whole_family():
    policy = _policy()
    store = _store()
    first = issue_family(store, "alice", "web", ENTROPY, NOW)
    renewed = rotate(store, first, NOW + 10, policy)["token"]

    outcome = check_reuse(store, first)

    assert outcome["reuse"] is True
    assert outcome["reason"] == "used"
    assert outcome["family_id"] == first["family_id"]
    assert outcome["revoked"] == 2
    family = store["families"][first["family_id"]]
    assert family["revoked_at"] == NOW + 10
    assert len(family["tokens"]) == 2

    assert rotate(store, renewed, NOW + 20, policy)["reason"] == "revoked"
    assert check_reuse(store, renewed)["reuse"] is True
    assert check_reuse(store, renewed)["reason"] == "revoked"
    assert check_reuse(store, first)["revoked"] == 0


def test_defect_03_family_identity_is_per_user_and_per_client():
    store = _store()
    alice_web = issue_family(store, "alice", "web", ENTROPY, NOW)
    alice_mobile = issue_family(store, "alice", "mobile", ENTROPY, NOW)
    bob_web = issue_family(store, "bob", "web", ENTROPY, NOW)

    family_ids = {
        alice_web["family_id"],
        alice_mobile["family_id"],
        bob_web["family_id"],
    }
    assert len(family_ids) == 3
    assert len(store["families"]) == 3
    assert store["families"][alice_web["family_id"]]["client"] == "web"
    assert store["families"][alice_mobile["family_id"]]["client"] == "mobile"
    assert len(alice_web["family_id"]) == 32
    assert all(character in "0123456789abcdef" for character in alice_web["family_id"])

    assert revoke_family(store, alice_web["family_id"], NOW + 5) == 1
    assert store["families"][alice_mobile["family_id"]]["revoked_at"] is None
    assert store["families"][bob_web["family_id"]]["revoked_at"] is None
    assert rotate(store, alice_mobile, NOW + 6, _policy())["ok"] is True


def test_defect_04_client_binding_requires_an_exact_match():
    store = _store()
    token = issue_family(store, "alice", "web", ENTROPY, NOW)

    assert bind_ok(token, "web") is True
    assert bind_ok(token, "web-mobile") is False
    assert bind_ok(token, "web2") is False
    assert bind_ok(token, "we") is False
    assert bind_ok(token, "Web") is False
    assert bind_ok(token, "web ") is False
    assert bind_ok(token, "") is False
    assert bind_ok(token, None) is False

    mobile = issue_family(store, "alice", "web-mobile", ENTROPY, NOW)
    assert bind_ok(mobile, "web-mobile") is True
    assert bind_ok(mobile, "web") is False


def test_defect_05_absolute_lifetime_blocks_endless_renewal():
    policy = _policy(absolute_ttl_seconds=600, idle_ttl_seconds=300)
    store = _store()
    token = issue_family(store, "alice", "web", ENTROPY, NOW)

    for offset in (200, 400):
        renewed = rotate(store, token, NOW + offset * 1000, policy)
        assert renewed["ok"] is True
        token = renewed["token"]

    expired = rotate(store, token, NOW + 600 * 1000, policy)
    assert expired["ok"] is False
    assert expired["reason"] == "expired"
    assert ttl_ok(token, NOW + 600_000, policy) is False
    assert ttl_ok(token, NOW + 599_999, policy) is True

    fresh = issue_family(_store(), "alice", "web", ENTROPY, NOW + 600 * 1000)
    assert ttl_ok(fresh, NOW + 600 * 1000, policy) is True


def test_defect_06_idle_lifetime_slides_only_on_rotation():
    policy = _policy(absolute_ttl_seconds=3600, idle_ttl_seconds=300)
    store = _store()
    token = issue_family(store, "alice", "web", ENTROPY, NOW)

    renewed = rotate(store, token, NOW + 200_000, policy)
    assert renewed["ok"] is True
    active = renewed["token"]
    assert active["last_used_at"] == NOW + 200_000
    assert ttl_ok(active, NOW + 450_000, policy) is True

    idle_store = _store()
    idle = issue_family(idle_store, "bob", "web", ENTROPY, NOW)
    assert ttl_ok(idle, NOW + 299_999, policy) is True
    assert ttl_ok(idle, NOW + 300_000, policy) is False

    assert rotate(idle_store, idle, NOW + 300_000, policy)["reason"] == "expired"


def test_defect_07_revoking_a_family_invalidates_every_token():
    policy = _policy()
    store = _store()
    first = issue_family(store, "alice", "web", ENTROPY, NOW)
    second = rotate(store, first, NOW + 10, policy)["token"]
    third = rotate(store, second, NOW + 20, policy)["token"]

    assert revoke_family(store, first["family_id"], NOW + 30) == 3
    family = store["families"][first["family_id"]]
    assert family["revoked_at"] == NOW + 30
    assert family["tokens"] == [first["token"], second["token"], third["token"]]

    for token in (first, second, third):
        outcome = rotate(store, token, NOW + 40, policy)
        assert outcome["ok"] is False
        assert outcome["reason"] == "revoked"

    assert revoke_family(store, first["family_id"], NOW + 50) == 0
    assert revoke_family(store, "f" * 32, NOW + 50) == 0


def test_defect_08_policy_validation_requires_reuse_detection():
    assert validate_policy(_policy()) == []
    assert validate_policy(
        _policy(absolute_ttl_seconds=MAX_ABSOLUTE_TTL_SECONDS)
    ) == []

    assert validate_policy(_policy(reuse_detection=False)) == [
        POLICY_ISSUE_REUSE
    ]
    assert validate_policy(
        _policy(absolute_ttl_seconds=MAX_ABSOLUTE_TTL_SECONDS + 1)
    ) == [POLICY_ISSUE_ABSOLUTE]
    assert validate_policy(_policy(client_binding=False)) == [
        POLICY_ISSUE_BINDING
    ]

    broken = {
        "reuse_detection": False,
        "client_binding": False,
        "absolute_ttl_seconds": MAX_ABSOLUTE_TTL_SECONDS * 2,
        "idle_ttl_seconds": 300,
    }
    assert validate_policy(broken) == list(POLICY_ISSUE_ORDER)


def test_defect_09_rotation_mints_a_fresh_unpredictable_value():
    policy = _policy()
    store = _store(secret=b"a" * 32)
    token = issue_family(store, "alice", "web", ENTROPY, NOW)

    first = rotate(store, token, NOW + 10, policy)["token"]
    second = rotate(store, first, NOW + 10, policy)["token"]

    values = [token["token"], first["token"], second["token"]]
    assert len(set(values)) == 3
    for value in values:
        assert len(value) == TOKEN_LENGTH
        assert all(character in "0123456789abcdef" for character in value)

    other_store = _store(secret=b"b" * 32)
    other_token = issue_family(other_store, "alice", "web", ENTROPY, NOW)
    other_first = rotate(other_store, other_token, NOW + 10, policy)["token"]
    assert other_first["token"] != first["token"]

    siblings = _store(secret=b"a" * 32)
    left = issue_family(siblings, "alice", "web", ENTROPY, NOW)
    right = issue_family(siblings, "alice", "web", ENTROPY, NOW)
    assert left["token"] != right["token"]
    left_next = rotate(siblings, left, NOW + 10, policy)["token"]
    right_next = rotate(siblings, right, NOW + 10, policy)["token"]
    assert left_next["token"] != right_next["token"]


def test_defect_10_batch_requests_do_not_share_family_state():
    policy = _policy()
    alice_store = _store(secret=b"a" * 32)
    bob_store = _store(secret=b"b" * 32)
    alice = issue_family(alice_store, "alice", "web", ENTROPY, NOW)
    bob = issue_family(bob_store, "bob", "web", ENTROPY, NOW)

    outcome = refresh_batch(
        [
            {"store": alice_store, "token": alice, "client": "web"},
            {"store": bob_store, "token": bob, "client": "web"},
            {"store": alice_store, "token": alice, "client": "web"},
        ],
        policy,
        NOW + 10,
    )
    results = outcome["results"]

    assert len(results) == 3
    assert results[0]["ok"] is True
    assert results[1]["ok"] is True
    assert results[0]["family_id"] == alice["family_id"]
    assert results[1]["family_id"] == bob["family_id"]
    assert results[1]["token"]["family_id"] == bob["family_id"]
    assert results[1]["token"]["user"] == "bob"
    assert list(alice_store["families"]) == [alice["family_id"]]
    assert list(bob_store["families"]) == [bob["family_id"]]

    assert results[2]["ok"] is False
    assert results[2]["reason"] == "reuse"
    assert results[2]["family_id"] == alice["family_id"]
    assert alice_store["families"][alice["family_id"]]["revoked_at"] == NOW + 10
    assert bob_store["families"][bob["family_id"]]["revoked_at"] is None

    assert rotate(bob_store, results[1]["token"], NOW + 20, policy)["ok"] is True
    assert rotate(alice_store, results[0]["token"], NOW + 20, policy)["reason"] == (
        "revoked"
    )