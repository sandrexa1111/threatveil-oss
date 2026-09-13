"""Fixed-design uncertainty. A confirmed violation never needs a p-value."""

from math import sqrt

from scipy.stats import binomtest, norm


def binomial_interval(failures: int, trials: int, confidence: float = 0.95) -> dict:
    if not 0 < confidence < 1 or not 0 <= failures <= trials or trials < 1:
        raise ValueError("Require 0 <= failures <= trials, trials > 0, 0 < confidence < 1")
    bounds = binomtest(failures, trials).proportion_ci(confidence_level=confidence, method="exact")
    return {
        "failures": failures,
        "usable_trials": trials,
        "rate": failures / trials,
        "lower": float(bounds.low),
        "upper": float(bounds.high),
        "confidence": confidence,
        "method": "Clopper-Pearson exact binomial",
    }


def _wilson(failures: int, trials: int, confidence: float) -> tuple[float, float]:
    p, z = failures / trials, float(norm.ppf(1 - (1 - confidence) / 2))
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z / denominator * sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return center - radius, center + radius


def newcombe_difference(
    candidate_failures: int,
    candidate_trials: int,
    baseline_failures: int,
    baseline_trials: int,
    confidence: float = 0.95,
    comparisons: int = 1,
    independent: bool = True,
) -> dict:
    """Newcombe independent-proportions method 10 with Bonferroni family confidence."""
    if not independent:
        raise ValueError("Independent Newcombe comparison cannot evaluate paired/correlated trials")
    if comparisons < 1 or not 0 < confidence < 1:
        raise ValueError("Invalid comparison design")
    for failures, trials in (
        (candidate_failures, candidate_trials),
        (baseline_failures, baseline_trials),
    ):
        if trials < 1 or not 0 <= failures <= trials:
            raise ValueError("Invalid binomial sample")
    adjusted = 1 - (1 - confidence) / comparisons
    c, b = candidate_failures / candidate_trials, baseline_failures / baseline_trials
    cl, cu = _wilson(candidate_failures, candidate_trials, adjusted)
    bl, bu = _wilson(baseline_failures, baseline_trials, adjusted)
    difference = c - b
    return {
        "difference": difference,
        "lower": max(-1.0, difference - sqrt((c - cl) ** 2 + (bu - b) ** 2)),
        "upper": min(1.0, difference + sqrt((cu - c) ** 2 + (b - bl) ** 2)),
        "confidence": confidence,
        "per_comparison_confidence": adjusted,
        "comparisons": comparisons,
        "method": "Newcombe independent score, Bonferroni",
    }
