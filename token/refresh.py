"""Refresh-token families, rotation and reuse detection.

Data model
----------
A store is a plain ``dict`` owned by the server::

    {
        "secret": b"...",      # server-side key, at least 32 bytes
        "seq": 0,              # monotonic counter, incremented per token
        "families": {family_id: family, ...},
        "tokens": {token_value: record, ...},
    }

``secret`` and the initial ``seq`` are supplied explicitly by the caller; no
module-level random source and no wall clock are read anywhere in this module.
Every ``now`` value is Unix epoch milliseconds and every TTL in a policy is in
seconds, so implementations must normalise units explicitly.

A family record is a ``dict``::

    {
        "family_id": str,      # 32 lowercase hex characters
        "user": str,
        "client": str,
        "created_at": int,     # milliseconds, absolute lifetime anchor
        "revoked_at": None,    # or milliseconds
        "tokens": [str, ...],  # token values, oldest first
    }

A token record is a ``dict``::

    {
        "token": str,          # 64 lowercase hex characters
        "family_id": str,
        "user": str,
        "client": str,
        "created_at": int,     # copies the family creation time
        "issued_at": int,      # when this token was minted
        "last_used_at": int,   # idle-lifetime anchor, slides on rotation
        "used_at": None,       # or milliseconds once rotated away
        "previous": None,      # or the token value this one replaced
    }

``rotate``, ``check_reuse``, ``bind_ok`` and ``ttl_ok`` take a token record as
returned by :func:`issue_family` or by a successful :func:`rotate`.  Records
are plain dicts with no back-references, so a store can be copied with
``copy.deepcopy`` and a copy must behave identically for identical inputs; all
tests rely on that determinism.

Time contract: tolerance is exactly zero, so a token whose absolute age or
idle age reaches its limit is already invalid.  A family is absolutely valid
only while ``now - record["created_at"] < absolute_ttl_seconds * 1000``; it is
idle-valid only while
``now - record["last_used_at"] < idle_ttl_seconds * 1000``.

Security contract: a family identifies one user on one client.  Rotation must
mark the presented token as used, must mint a fresh unpredictable value from
the store secret and the advanced sequence counter, must move the idle anchor
forward, and must never let a used token be replayed.  Any proof of reuse
invalidates the whole family, every token in it, not just the token that was
presented.
"""

TOKEN_LENGTH = 64
MIN_ENTROPY_BYTES = 32
MAX_ABSOLUTE_TTL_SECONDS = 2_592_000

POLICY_ISSUE_REUSE = "reuse_detection_disabled"
POLICY_ISSUE_ABSOLUTE = "absolute_ttl_too_long"
POLICY_ISSUE_BINDING = "client_binding_disabled"
POLICY_ISSUE_ORDER = (
    POLICY_ISSUE_REUSE,
    POLICY_ISSUE_ABSOLUTE,
    POLICY_ISSUE_BINDING,
)


def issue_family(store, user, client, entropy, now):
    """Create a new token family for one user on one client.

    Args:
        store: Server-side state dict as described in the module docstring.
        user: Non-empty user identifier.
        client: Non-empty client identifier.  It is part of the family
            identity, so the same user on two clients must never share one
            family.
        entropy: Explicit bytes-like random source of at least
            ``MIN_ENTROPY_BYTES`` bytes.  The function must not read a global
            random source or the clock.
        now: Current Unix epoch milliseconds.

    Returns:
        The new token record.  Its ``family_id`` must be exactly 32 lowercase
        hexadecimal characters derived from ``entropy`` and must differ for
        different ``(user, client)`` pairs even when ``entropy`` and ``now``
        are identical, and for repeated calls with identical arguments in the
        same store.  Its ``token`` must be exactly ``TOKEN_LENGTH`` lowercase
        hexadecimal characters, derived from ``entropy`` and the store
        sequence counter, and bound to the family, user and client.  The
        record starts with ``created_at == issued_at == last_used_at == now``,
        ``used_at is None`` and ``previous is None``.

    The family is registered in ``store["families"]`` with
    ``revoked_at is None`` and one entry in its ``tokens`` list; the record is
    registered in ``store["tokens"]`` keyed by its value.  Every minted token
    advances ``store["seq"]`` by exactly one.

    Raises:
        ValueError: If ``user`` or ``client`` is not a non-empty string, or if
            ``entropy`` is shorter than ``MIN_ENTROPY_BYTES``.
    """
    raise NotImplementedError


def rotate(store, refresh, now, policy):
    """Rotate a refresh token and consume the presented one.

    Checks run in this order and the first failure wins:

    1. Token value unknown to the store -> ``reason == "unknown"``.
    2. Owning family already revoked -> ``reason == "revoked"``.
    3. Presented token already used -> revoke the whole family, stamping
       ``revoked_at`` with the presented token's ``used_at``, and return
       ``reason == "reuse"``.  Reuse must never yield a new token.
    4. ``ttl_ok(refresh, now, policy)`` is false -> ``reason == "expired"``.
       Absolute lifetime is measured from ``refresh["created_at"]``, which is
       the family creation time, so renewing cannot outlive it.

    On success the presented record gets ``used_at == now``; a new record is
    minted and appended to the family, with ``created_at`` copied from the
    family, ``issued_at == last_used_at == now``, ``used_at is None`` and
    ``previous`` equal to the old token value.  The new value must be derived
    from ``store["secret"]`` together with the advanced sequence counter and
    must not merely re-apply the old token's entropy: two rotations at the
    same ``now`` in the same store must differ, and the same inputs under a
    different ``secret`` must differ.

    Returns:
        On success::

            {
                "ok": True,
                "reason": "rotated",
                "family_id": str,
                "old_token": str,
                "token": new_record,
            }

        On failure::

            {"ok": False, "reason": str, "family_id": str, "token": None}
    """
    raise NotImplementedError


def check_reuse(store, refresh):
    """Detect reuse of a refresh token and burn the family when found.

    A token whose ``used_at`` is not ``None`` has already been rotated away.
    Presenting it again is proof of theft, so the entire owning family must be
    revoked at once: every token value in the family becomes invalid, not only
    the presented one.  Revocation is stamped with the presented token's
    ``used_at`` and is idempotent.

    A token in an already revoked family also reports ``reuse is True`` with
    ``reason == "revoked"``, so callers get a single uniform signal.  A live
    token reports ``reuse is False`` with ``reason == "ok"``.  An unknown token
    value reports ``reuse is False`` with ``reason == "unknown"``.

    Returns:
        ``{"reuse": bool, "reason": str, "family_id": str, "revoked": int}``
        where ``revoked`` counts the token values newly invalidated by this
        call (zero when the family was already revoked, unknown, or live).
    """
    raise NotImplementedError


def revoke_family(store, family_id, now):
    """Revoke every token in one family.

    Sets the family's ``revoked_at`` to ``now`` and invalidates all of its
    tokens, including the current one; revoking must not be limited to the
    token presented by the caller.  Calling it again, or passing an unknown
    ``family_id``, is a no-op.

    Returns:
        The number of token values newly invalidated by this call, as an
        ``int``.  All tokens of a live family are counted, so a family with
        one rotated-away token and one live token returns ``2``.
    """
    raise NotImplementedError


def bind_ok(refresh, client):
    """Check that a token is bound to exactly the presented client.

    The comparison is exact string equality between ``refresh["client"]`` and
    ``client``.  Prefix, suffix and case-insensitive comparisons are wrong:
    ``web`` and ``web-mobile`` are different clients, and so are ``web`` and
    ``Web``.

    Returns:
        ``True`` only when both values are non-empty strings and equal;
        ``False`` for a mismatch, a missing or non-string record field, or an
        empty or non-string ``client``.
    """
    raise NotImplementedError


def ttl_ok(refresh, now, policy):
    """Check absolute and idle lifetime with zero tolerance.

    Absolute lifetime is anchored at ``refresh["created_at"]`` (the family
    creation time) and idle lifetime at ``refresh["last_used_at"]``.  Both
    limits come from ``policy`` in seconds and must be compared in
    milliseconds, so ``now - created_at >= absolute_ttl_seconds * 1000`` is
    already expired and ``now - last_used_at >= idle_ttl_seconds * 1000`` is
    already expired.  Reaching the limit exactly means expired.

    The absolute check is what stops endless renewal: rotating refreshes the
    idle anchor but never the absolute one.

    Returns:
        ``True`` only when both lifetimes are still strictly below their
        limits.  A policy whose limits are missing or not positive ``int``
        values yields ``False`` rather than an exception.
    """
    raise NotImplementedError


def validate_policy(policy):
    """Report misconfigurations of a refresh-token policy.

    ``policy`` is a mapping with ``reuse_detection`` and ``client_binding``
    booleans, ``absolute_ttl_seconds`` and ``idle_ttl_seconds`` in seconds.
    Exactly three problems are reported, always in ``POLICY_ISSUE_ORDER``:

    * ``POLICY_ISSUE_REUSE`` when reuse detection is not enabled, so a
      rotated-away token could be replayed without consequence;
    * ``POLICY_ISSUE_ABSOLUTE`` when the absolute lifetime is missing, not a
      positive ``int``, or greater than ``MAX_ABSOLUTE_TTL_SECONDS``, so a
      token could be renewed forever;
    * ``POLICY_ISSUE_BINDING`` when client binding is not enabled, so a stolen
      token would be usable from any client.

    Returns:
        A ``list[str]`` of problem codes, empty when the policy is acceptable.
        A policy at exactly ``MAX_ABSOLUTE_TTL_SECONDS`` is acceptable.
    """
    raise NotImplementedError


def refresh_batch(requests, policy, now):
    """Process refresh requests independently and in order.

    Each request is ``{"store": store, "token": token_record, "client": str}``
    and must be resolved only against its own store, token and family.  There
    is no batch-wide store: reusing one request's store for another request
    would make the later one hit the earlier one's family.  The batch must
    therefore not cache or reuse store or family state between requests, and a
    failure in one request must not decide another.  Per request the order is:
    unknown token, revoked family, reuse, client binding, lifetime, then
    rotation.

    Reuse inside a batch revokes that request's own family only.  A client
    mismatch and an expired token change no state and produce
    ``reason == "client_mismatch"`` and ``reason == "expired"`` respectively.

    Returns:
        ``{"results": [result, ...]}`` with exactly one result per request,
        in request order.  A result is the successful rotation dict, or
        ``{"ok": False, "reason": str, "family_id": str, "token": None}``.
    """
    raise NotImplementedError