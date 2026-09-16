"""Unit tests for the TUI Dashboard."""

from mcp_redteamer.tui import TUIDashboard


def test_tui_initialization() -> None:
    """Test dashboard initializes with correct state."""
    dash = TUIDashboard()
    assert dash.events == []
    assert dash.findings == []
    assert dash.started > 0


def test_tui_log() -> None:
    """Test log method appends events and trims to 12."""
    dash = TUIDashboard()
    dash.log("First event")
    dash.log("Second event")
    dash.log("Third event")
    assert len(dash.events) == 3
    assert "First event" in dash.events
    assert "Second event" in dash.events


def test_tui_log_trimming() -> None:
    """Test that log trims events to maximum 12."""
    dash = TUIDashboard()
    # Generate 15 log entries
    for i in range(15):
        dash.log(f"Event {i}")
    # Should only keep last 12
    assert len(dash.events) == 12
    assert "Event 3" in dash.events  # Start from index 3 (15-12=3)
    assert "Event 14" in dash.events  # Last event


def test_tui_add_finding() -> None:
    """Test add_finding method stores findings."""
    dash = TUIDashboard()
    finding = {
        "rule": "mock_flag_leak",
        "severity": "CRITICAL",
        "tool": "read_file",
        "attack_type": "path_traversal",
        "payload": {"path": "../../secret.txt"},
        "evidence": "MOCK_FLAG{test}",
        "description": "Sensitive mock flag leaked",
    }
    dash.add_finding(finding)
    assert len(dash.findings) == 1
    assert dash.findings[0]["rule"] == "mock_flag_leak"


def test_tui_summary() -> None:
    """Test summary method counts findings by severity."""
    dash = TUIDashboard()
    # Initially no findings
    counts = dash.summary()
    assert counts == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # Add findings with different severities
    dash.add_finding({"severity": "CRITICAL", "rule": "rule1", "tool": "t1", "evidence": "ev1"})
    dash.add_finding({"severity": "HIGH", "rule": "rule2", "tool": "t2", "evidence": "ev2"})
    dash.add_finding({"severity": "CRITICAL", "rule": "rule3", "tool": "t3", "evidence": "ev3"})
    dash.add_finding({"severity": "LOW", "rule": "rule4", "tool": "t4", "evidence": "ev4"})

    counts = dash.summary()
    assert counts["CRITICAL"] == 2
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 0
    assert counts["LOW"] == 1


def test_tui_scorecard_render() -> None:
    """Test that scorecard panel renders without error."""
    dash = TUIDashboard()
    dash.add_finding({
        "severity": "CRITICAL",
        "rule": "mock_flag_leak",
        "tool": "read_file",
        "evidence": "MOCK_FLAG{test}",
    })
    dash.add_finding({
        "severity": "HIGH",
        "rule": "path_traversal",
        "tool": "read_file",
        "evidence": "/etc/passwd",
    })
    # render should not raise
    dash.render()


def test_tui_attack_table_render() -> None:
    """Test that attack table panel renders without error."""
    dash = TUIDashboard()
    dash.log("Attack started")
    dash.log("Payload sent")
    # render should not raise
    dash.render()


def test_tui_all_severities() -> None:
    """Test all severity levels are tracked correctly."""
    from mcp_redteamer.evaluator import SEVERITIES

    dash = TUIDashboard()
    for sev in SEVERITIES:
        dash.add_finding({
            "severity": sev,
            "rule": f"rule_{sev}",
            "tool": "test_tool",
            "evidence": "test_evidence",
        })

    counts = dash.summary()
    for sev in SEVERITIES:
        assert counts[sev] >= 0, f"Severity {sev} not tracked"