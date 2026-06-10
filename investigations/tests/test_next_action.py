"""The 'Next step' strip + every empty state are driven by one source of truth:
_next_action(stages) = the first lifecycle stage that isn't done. This guarantees
every room shows the single correct next move (ui-ux-pro-max `primary-action`).

Run: .venv/bin/python -m investigations.tests.test_next_action
"""
from investigations.webapp.app import _next_action


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _stage(key, num, done, count=None):
    return {"key": key, "num": num, "label": key.title(), "href": f"/{key}",
            "done": done, "count": count}


# The schema/Understand stage is gone (auto-modeled inside Process, no analyst
# step — founder decision 2026-06-10). Lifecycle: Intake → Investigate →
# Deliver → Portfolio.
ORDER = [("intake", 1), ("investigate", 2), ("deliver", 3), ("portfolio", 4)]


def _stages(done_keys, counts=None):
    counts = counts or {}
    return [_stage(k, n, k in done_keys, counts.get(k)) for k, n in ORDER]


def test_next_action():
    # None for all/multi-case (no stages).
    _check("no stages → None", _next_action(None) is None)

    # Fresh case: nothing done → next is Intake.
    na = _next_action(_stages(set()))
    _check("nothing done → intake", na["key"] == "intake" and na["href"] == "/reports")

    # Ingested but no agent runs → Investigate (schema is auto, no Understand step).
    na = _next_action(_stages({"intake"}))
    _check("ingested → investigate", na["key"] == "investigate")
    _check("carries a hint", bool(na.get("hint")))
    # The 'already done' payoff surfaces done stages with content (deliver, or a count).
    na = _next_action(_stages({"intake"}, {"investigate": 4}))

    # Everything done → point at the brief.
    na = _next_action(_stages({k for k, _ in ORDER}, {"findings": 4, "portfolio": 2}))
    _check("all done → open the brief", na["key"] == "done" and na["href"] == "/synthesis")


def main():
    test_next_action()
    print("\nPASS: test_next_action")


if __name__ == "__main__":
    main()
