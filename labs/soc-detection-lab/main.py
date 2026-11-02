"""Command line interface for offline SOC detection lab."""
import argparse
import json
from pathlib import Path
import sys
from detector import EventError, analyze, load_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic authentication logs offline")
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "data" / "auth_events.jsonl")
    parser.add_argument("--output", type=Path, help="Write findings to JSON instead of stdout")
    args = parser.parse_args()
    try:
        events = load_jsonl(args.input)
        findings = analyze(events)
        document = {"input_events": len(events), "alert_count": len(findings), "alerts": findings}
        result = json.dumps(document, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result, encoding="utf-8")
            print(f"Wrote {len(findings)} alerts to {args.output}")
        else:
            print(result, end="")
        return 0
    except (OSError, EventError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
