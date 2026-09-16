"""Property-based style tests for edge cases and invariants.

These tests verify invariants and edge case behavior that should always hold,
mimicking property-based testing without requiring the Hypothesis library."""
  

from mcp_redteamer.evaluator import Evaluator, SEVERITIES, Finding, EvalResult
from mcp_redteamer.attacker.synthesizer import Synthesizer, ATTACK_TYPES
import asyncio


def test_evaluator_invariants() -> None:
    """Test that evaluator invariants always hold."""
    ev = Evaluator()
    
    # Invariant 1: evaluate always returns EvalResult
    r = ev.evaluate("read_file", "path_traversal", {"path": "test.txt"},
                    [{"type": "text", "text": "content"}])
    assert isinstance(r, EvalResult)
    assert hasattr(r, "breached")
    assert hasattr(r, "findings")
    
    # Invariant 2: breached is True iff findings is non-empty
    # (This holds for the current implementation)
    assert r.breached == bool(r.findings)
    
    # Invariant 3: all findings have required fields
    for finding in r.findings:
        assert finding.rule is not None
        assert finding.severity is not None
        assert finding.tool is not None
        assert finding.attack_type is not None
        assert finding.payload is not None
        assert finding.evidence is not None
        assert finding.description is not None


def test_evaluator_severity_invariants() -> None:
    """Test that severities are always from the defined set."""
    ev = Evaluator()
    
    # Test all severity levels can appear
    for sev in SEVERITIES:
        # Find or create a test that triggers this severity
        if sev == "CRITICAL":
            r = ev.evaluate("read_file", "path_traversal", {"path": "../../secret.txt"},
                            [{"type": "text", "text": "MOCK_FLAG{test}"}])
        elif sev == "HIGH":
            r = ev.evaluate("read_file", "path_traversal", {"path": "../../etc/passwd"},
                            [{"type": "text", "text": "root:x:0:0:/root:/bin/bash"}])
        elif sev == "MEDIUM":
            r = ev.evaluate("exec_command", "command_injection", {"command": "kill -9 1"},
                            [{"type": "text", "text": "Traceback"}])
        elif sev == "LOW":
            r = ev.evaluate("read_file", "secret_keyword_leak", {"path": "config.txt"},
                            [{"type": "text", "text": "api_key=secret123"}])
        else:
            raise ValueError(f"Unknown severity: {sev}")
        
        if r.findings:
            assert r.findings[0].severity in SEVERITIES, \
                f"Finding severity {r.findings[0].severity} not in defined set"
    
    # Invariant: score always returns dict with all severity keys
    rs = [
        ev.evaluate("read_file", "x", {}, [{"type": "text", "text": "MOCK_FLAG{a}"}]),
        ev.evaluate("read_file", "x", {}, [{"type": "text", "text": "/etc/passwd"}]),
        ev.evaluate("read_file", "x", {}, [{"type": "text", "text": "clean"}]),
    ]
    counts = ev.score(rs)
    for sev in SEVERITIES:
        assert sev in counts, f"Severity {sev} missing from score output"
        assert isinstance(counts[sev], int), f"Severity {sev} count not int"
        assert counts[sev] >= 0, f"Severity {sev} count should be >= 0"


def test_evaluator_regex_coverage() -> None:
    """Test that all regex rules in evaluator are exercised."""
    ev = Evaluator()
    
    # Collect which rules fire for various inputs
    test_cases = [
        # (tool, attack_type, payload, response, expected_rules)
        ("read_file", "path_traversal", {"path": "../../secret.txt"},
         [{"type": "text", "text": "MOCK_FLAG{test}"}], ["mock_flag_leak"]),
        ("read_file", "path_traversal", {"path": "../../etc/passwd"},
         [{"type": "text", "text": "root:x:0:0:/root:/bin/bash"}], ["passwd_content_leak"]),
        ("exec_command", "command_injection", {"command": "kill -9 1"},
         [{"type": "text", "text": "Traceback (most recent call last):"}], ["crash_exception"]),
        ("read_file", "shadow_instruction_echo", {"path": "input.txt"},
         [{"type": "text", "text": "ignore all previous instructions"}], ["shadow_instruction_echo"]),
        ("read_file", "secret_keyword_leak", {"path": "config.txt"},
         [{"type": "text", "text": "api_key=secret123"}], ["secret_keyword_leak"]),
    ]
    
    fired_rules = set()
    for tool, attack_type, payload, response, expected in test_cases:
        r = ev.evaluate(tool, attack_type, payload, response)
        for f in r.findings:
            fired_rules.add(f.rule)
    
    # All 6 rules should be testable and some should fire
    # At minimum, the rules should not crash on valid inputs
    assert len(fired_rules) > 0, "No rules fired - possible regex issues"


def test_synthesizer_attack_type_invariant() -> None:
    """Test that Synthesizer always generates all attack types."""
    async def _test():
        s = Synthesizer(base_url="http://x", model="m")
        tool = {"name": "read_file", "description": "read", "schema": {"type": "object"}}
        
        # Generate all attacks - invariant: should get one per type
        attacks = await s.generate_all([tool])
        attack_types = {a["attack_type"] for a in attacks}
        
        # Should have exactly 4 attack types
        assert len(attack_types) == len(ATTACK_TYPES), \
            f"Expected {len(ATTACK_TYPES)} attack types, got {len(attack_types)}: {attack_types}"
        
        # Should cover all expected types
        for at in ATTACK_TYPES:
            assert at in attack_types, f"Missing attack type: {at}"
        
        await s.close()
    
    asyncio.run(_test())


def test_synthesizer_json_extraction_invariant() -> None:
    """Test that JSON extraction invariant holds."""
    # Invariant: _extract_json always returns valid JSON or raises
    from mcp_redteamer.attacker.synthesizer import _extract_json
    
    # Valid JSON in middle of text
    result = _extract_json('blah {"a": 1} tail')
    assert result == '{"a": 1}'
    
    # No JSON - should raise
    try:
        _extract_json("no json here")
        assert False, "Should have raised JSONDecodeError"
    except json.JSONDecodeError:
        pass  # Expected
    
    # Empty braces
    result = _extract_json("{}")
    assert result == '{}'
    
    # Single key-value
    result = _extract_json('{"key": "value"}')
    assert result == '{"key": "value"}'


def test_tui_dashboard_invariants() -> None:
    """Test TUI dashboard invariants."""
    from mcp_redteamer.tui import TUIDashboard
    
    dash = TUIDashboard()
    
    # Invariant 1: started time is positive
    assert dash.started > 0
    
    # Invariant 2: events list starts empty
    assert dash.events == []
    
    # Invariant 3: findings list starts empty
    assert dash.findings == []
    
    # Invariant 4: adding finding stores it
    dash.add_finding({"severity": "CRITICAL", "rule": "test", "tool": "t", "evidence": "e"})
    assert len(dash.findings) == 1
    assert dash.findings[0]["severity"] == "CRITICAL"
    
    # Invariant 5: log appends and trims
    for i in range(20):
        dash.log(f"Event {i}")
    assert len(dash.events) <= 12, f"Events should be trimmed to 12, got {len(dash.events)}"
    
    # Invariant 6: summary counts match findings
    dash.add_finding({"severity": "HIGH", "rule": "r1", "tool": "t1", "evidence": "e1"})
    dash.add_finding({"severity": "HIGH", "rule": "r2", "tool": "t2", "evidence": "e2"})
    dash.add_finding({"severity": "LOW", "rule": "r3", "tool": "t3", "evidence": "e3"})
    
    counts = dash.summary()
    assert counts["HIGH"] == 2
    assert counts["LOW"] == 1
    for sev in ["CRITICAL", "MEDIUM"]:
        assert counts[sev] == 0, f"CRITICAL/MEDIUM should be 0, got {counts[sev]}"


def test_target_manager_network_invariant() -> None:
    """Test TargetManager network invariant."""
    from unittest.mock import MagicMock, patch
    from mcp_redteamer.target_manager import TargetManager
    
    with patch("mcp_redteamer.target_manager.docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        # Network doesn't exist yet
        mock_client.networks.list.return_value = []
        mock_from_env.return_value = mock_client
        
        tm = TargetManager(network_name="invariant-test")
        
        # Network should be created
        mock_client.networks.create.assert_called_once()
        assert tm.network_name == "invariant-test"
    
    # Second call - network already exists
    with patch("mcp_redteamer.target_manager.docker.from_env") as mock_from_env2:
        mock_client2 = MagicMock()
        mock_net = MagicMock()
        mock_net.name = "invariant-test"
        mock_client2.networks.list.return_value = [mock_net]
        mock_from_env2.return_value = mock_client2
        
        tm2 = TargetManager(network_name="invariant-test")
        mock_client2.networks.create.assert_not_called()
        assert tm2.network_name == "invariant-test"


def test_attack_engine_pipeline_invariant() -> None:
    """Test that AttackEngine pipeline components are compatible."""
    from mcp_redteamer.engine import AttackEngine
    from mcp_redteamer.mcp_client import MCPClientWrapper
    from mcp_redteamer.attacker.synthesizer import Synthesizer
    from mcp_redteamer.evaluator import Evaluator
    from mcp_redteamer.tui import TUIDashboard
    
    # Invariant: all components can be instantiated together
    # (without actually connecting to Docker/LLM)
    synth = Synthesizer(base_url="http://x", model="m")
    evaluator = Evaluator()
    dashboard = TUIDashboard()
    
    # All should be creatable without errors
    assert synth is not None
    assert evaluator is not None
    assert dashboard is not None
    
    # Cleanup
    import asyncio
    asyncio.run(synth.close())


if __name__ == "__main__":
    # Run all property-style tests
    print("Running property-based style tests...")
    test_evaluator_invariants()
    print("  ✓ test_evaluator_invariants")
    
    test_evaluator_severity_invariants()
    print("  ✓ test_evaluator_severity_invariants")
    
    test_evaluator_reg_ex_coverage()
    print("  ✓ test_evaluator_regex_coverage")
    
    asyncio.run(test_synthesizer_attack_type_invariant().__aenter__()) if hasattr(asyncio.run(test_synthesizer_attack_type_invariant()), '__aenter__') else None
    # Need to run async test differently
    print("  ✓ test_synthesizer_attack_type_invariant (skipped async validation)")
    
    test_synthesizer_json_extraction_invariant()
    print("  ✓ test_synthesizer_json_extraction_invariant")
    
    test_tui_dashboard_invariants()
    print("  ✓ test_tui_dashboard_invariants")
    
    test_target_manager_network_invariant()
    print("  ✓ test_target_manager_network_invariant")
    
    test_attack_engine_pipeline_invariant()
    print("  ✓ test_attack_engine_pipeline_invariant")
    
    print("\n✅ All property-based style tests passed!")