#!/usr/bin/env bash
# Every example under contracts/examples/ must validate against its schema.
#
# Run by hand after editing a schema, and by CI on every push. A schema that no
# longer accepts its own example is the usual way these two drift apart, and it
# drifts silently: the seed script keeps emitting the old shape and the runbooks
# keep reading it, right up until somebody adds a field to one side only.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! python3 -c 'import jsonschema' 2>/dev/null; then
  echo "jsonschema is required: pip install jsonschema" >&2
  exit 1
fi

python3 - "$root" <<'PY'
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

root = Path(sys.argv[1])
pairs = [
    ("alert.schema.json", "alert.json"),
    ("soar-case.schema.json", "soar-case.json"),
    ("iocs.schema.json", "iocs.json"),
]

failed = False
for schema_name, example_name in pairs:
    schema = json.loads((root / "contracts" / schema_name).read_text())
    example = json.loads((root / "contracts" / "examples" / example_name).read_text())

    # check_schema first: an invalid schema silently accepts everything, so a
    # broken one would otherwise report as a pass.
    Draft202012Validator.check_schema(schema)

    errors = sorted(Draft202012Validator(schema).iter_errors(example), key=lambda e: e.path)
    if errors:
        failed = True
        print(f"FAIL {example_name}", file=sys.stderr)
        for error in errors:
            location = "/".join(str(p) for p in error.absolute_path) or "(root)"
            print(f"  {location}: {error.message}", file=sys.stderr)
    else:
        print(f"ok   {example_name} against {schema_name}")

sys.exit(1 if failed else 0)
PY
