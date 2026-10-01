import math

import numpy as np
import pytest

from netwatch.baseline import Ewma, GuardedBaseline


def test_early_samples_give_plain_mean_and_population_variance():
    # With alpha=0.1 the first 10 samples use weight 1/n, i.e. an ordinary average.
    data = [3.0, 7.0, 5.0, 9.0, 1.0, 6.0]
    e = Ewma(alpha=0.1)
    for x in data:
        e.update(x)
    assert e.mean == pytest.approx(np.mean(data))
    assert e.var == pytest.approx(np.var(data))


def test_steady_state_update_follows_ewma_formula():
    e = Ewma(alpha=0.25)
    for x in [10.0] * 8:  # past the warm start (1/alpha = 4 samples)
        e.update(x)
    mean, var = e.mean, e.var
    e.update(18.0)
    diff = 18.0 - mean
    assert e.mean == pytest.approx(mean + 0.25 * diff)
    assert e.var == pytest.approx((1 - 0.25) * (var + 0.25 * diff**2))


def test_mean_tracks_a_level_shift():
    e = Ewma(alpha=0.2)
    for _ in range(50):
        e.update(10.0)
    for _ in range(50):
        e.update(20.0)
    assert e.mean == pytest.approx(20.0, abs=0.01)


def test_zscore_sign_and_std_floors():
    e = Ewma(alpha=0.1, min_std=1.0, rel_std=0.1)
    for _ in range(20):
        e.update(100.0)  # perfectly flat: variance is 0
    assert e.var == 0
    assert e.std == pytest.approx(10.0)  # relative floor: 10% of the mean
    assert e.zscore(130.0) == pytest.approx(3.0)
    assert e.zscore(70.0) == pytest.approx(-3.0)
    tiny = Ewma(min_std=1.0, rel_std=0.1)
    tiny.update(0.0)
    assert tiny.std == 1.0  # absolute floor when the mean is ~0
    assert math.isfinite(tiny.zscore(5.0))


def test_alpha_is_validated():
    with pytest.raises(ValueError):
        Ewma(alpha=0)
    with pytest.raises(ValueError):
        Ewma(alpha=1.5)


def test_warmup_controls_readiness():
    b = GuardedBaseline(warmup=3)
    for i in range(3):
        assert not b.ready
        b.learn(10.0 + i, anomalous=False)
    assert b.ready


def test_anomalous_windows_do_not_pollute_baseline():
    b = GuardedBaseline(alpha=0.1, warmup=1, relearn_after=100)
    for _ in range(20):
        b.learn(50.0, anomalous=False)
    for _ in range(10):
        b.learn(5000.0, anomalous=True)
    assert b.mean == pytest.approx(50.0)


def test_baseline_relearns_after_a_lasting_change():
    b = GuardedBaseline(alpha=0.5, warmup=1, relearn_after=3)
    for _ in range(10):
        b.learn(50.0, anomalous=False)
    for _ in range(2):
        b.learn(500.0, anomalous=True)
    assert b.mean == pytest.approx(50.0)  # not yet: could still be a short attack
    for _ in range(10):
        b.learn(500.0, anomalous=True)
    assert b.mean > 400  # accepted as the new normal
