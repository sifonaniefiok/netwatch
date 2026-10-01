"""Exponentially weighted moving statistics: NetWatch's idea of "normal".

An EWMA (exponentially weighted moving average) keeps a running mean where
recent windows count more than old ones. Each update moves the mean a
fraction ``alpha`` of the way toward the new value:

    diff  = x - mean
    mean  = mean + alpha * diff
    var   = (1 - alpha) * (var + alpha * diff**2)

The variance line is the matching exponentially weighted variance (Finch,
"Incremental calculation of weighted mean and variance", 2009). Memory use is
three numbers per metric, and each update is O(1), which is why this is a
good fit for a streaming detector.

A z-score then says how unusual a new value is, measured in standard
deviations from the baseline: ``z = (x - mean) / std``.
"""

from __future__ import annotations

import math


class Ewma:
    """EWMA mean and variance of one metric."""

    def __init__(self, alpha: float = 0.1, min_std: float = 1.0, rel_std: float = 0.1) -> None:
        """
        Args:
            alpha: weight of the newest value, in (0, 1]. 0.1 means the baseline
                mostly reflects roughly the last 1/alpha = 10-20 windows.
            min_std: absolute floor for the standard deviation used in z-scores.
            rel_std: floor for the standard deviation as a fraction of the mean.

        The floors exist because perfectly steady traffic has a variance near
        zero, which would make a tiny wobble look infinitely surprising.
        """
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.min_std = min_std
        self.rel_std = rel_std
        self.mean = 0.0
        self.var = 0.0
        self.count = 0

    def update(self, x: float) -> None:
        """Fold ``x`` into the baseline.

        For the first ``1/alpha`` samples the weight is ``1/count`` instead of
        ``alpha``, which makes the early estimate a plain average. Without this,
        the very first value would dominate the mean for a long time and the
        variance would start out far too small.
        """
        self.count += 1
        weight = max(self.alpha, 1.0 / self.count)
        diff = x - self.mean
        self.mean += weight * diff
        self.var = (1.0 - weight) * (self.var + weight * diff * diff)

    @property
    def std(self) -> float:
        """Standard deviation used for z-scores, never below the configured floors."""
        return max(math.sqrt(self.var), self.min_std, self.rel_std * abs(self.mean))

    def zscore(self, x: float) -> float:
        """How many standard deviations ``x`` is above (+) or below (-) the mean."""
        return (x - self.mean) / self.std


class GuardedBaseline:
    """An :class:`Ewma` with a warm-up period and protection against pollution.

    *Warm-up*: the first ``warmup`` windows are only learned from; until then
    :attr:`ready` is False and detectors stay silent, because a baseline built
    from two or three samples would raise alerts on ordinary noise.

    *Pollution guard*: windows flagged as anomalous are not learned from.
    Otherwise a long attack would slowly drag the mean up until the attack
    itself looked normal. The exception is a lasting change: after
    ``relearn_after`` anomalous windows in a row, we assume the network has a
    new normal (a new backup job, a server going offline) and learn again, so
    the detector does not alert forever.
    """

    def __init__(
        self,
        alpha: float = 0.1,
        warmup: int = 10,
        relearn_after: int = 30,
        min_std: float = 1.0,
        rel_std: float = 0.1,
    ) -> None:
        self.ewma = Ewma(alpha=alpha, min_std=min_std, rel_std=rel_std)
        self.warmup = warmup
        self.relearn_after = relearn_after
        self.consecutive_anomalies = 0

    @property
    def ready(self) -> bool:
        return self.ewma.count >= self.warmup

    @property
    def mean(self) -> float:
        return self.ewma.mean

    def zscore(self, x: float) -> float:
        return self.ewma.zscore(x)

    def learn(self, x: float, anomalous: bool) -> None:
        """Update the baseline with ``x`` unless it was an anomaly (see class docs)."""
        if anomalous:
            self.consecutive_anomalies += 1
            if self.consecutive_anomalies < self.relearn_after:
                return
        else:
            self.consecutive_anomalies = 0
        self.ewma.update(x)
