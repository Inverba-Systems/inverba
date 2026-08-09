from inverba.seen import InMemorySeenStore, SeenStore


def test_unseen_key_is_false():
    store = InMemorySeenStore()
    assert store.seen("k") is False


def test_recorded_key_is_seen():
    store = InMemorySeenStore()
    store.record("k")
    assert store.seen("k") is True


def test_ttl_expiry_forgets_the_key():
    clock = {"t": 0.0}
    store = InMemorySeenStore(ttl_seconds=10, clock=lambda: clock["t"])
    store.record("k")
    clock["t"] = 5
    assert store.seen("k") is True      # within TTL
    clock["t"] = 11
    assert store.seen("k") is False     # past TTL -> forgotten


def test_ttl_measures_from_first_sighting_not_latest():
    clock = {"t": 0.0}
    store = InMemorySeenStore(ttl_seconds=10, clock=lambda: clock["t"])
    store.record("k")
    clock["t"] = 5
    store.record("k")                   # a second record() must not extend the TTL
    clock["t"] = 11
    assert store.seen("k") is False


def test_no_ttl_remembers_indefinitely():
    clock = {"t": 0.0}
    store = InMemorySeenStore(clock=lambda: clock["t"])
    store.record("k")
    clock["t"] = 10_000_000
    assert store.seen("k") is True


def test_in_memory_store_satisfies_protocol():
    assert isinstance(InMemorySeenStore(), SeenStore)
