"""
Unit test for AdaptiveShield Cyber Deception Benchmark Runner.
"""

import pytest
from deception.benchmark.run_deception_eval import run_benchmark


@pytest.mark.asyncio
async def test_deception_benchmark_execution():
    results = await run_benchmark()
    assert "AdaptiveShield (Ours)" in results
    assert "Static Honeypot (Cowrie/Dionaea)" in results
    assert "Naive LLM (Galah Baseline)" in results

    ours = results["AdaptiveShield (Ours)"]
    assert ours["mean_dwell_time_sec"] > results["Static Honeypot (Cowrie/Dionaea)"]["mean_dwell_time_sec"]
    assert ours["canary_attribution_events"] >= 1
    assert ours["avg_latency_ms"] < 15.0  # Under 15ms SLA
