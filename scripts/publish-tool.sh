#!/usr/bin/env bash
# Builds serverless-aws and publishes it as a public GitHub release asset, so the
# tool catalog can install it onto PATH via the `binary` install kind.
#
# Public on purpose: the tool holds no secret and no scenario answer -- the orphan
# is derived from evidence at run time, not baked in -- so it is a genuine,
# reusable AWS investigation CLI, not a demo artifact to hide. Publishing it is
# what lets the harness install it with a plain fetch and no credential.
#
# One command: build, upload, and print the exact tool-catalog values (URL +
# sha256) to paste into the product. Re-run to publish a new version; the sha256
# changes and the catalog entry has to be updated to match, which `verify` checks.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/harness/serverless-aws"

version="${1:-v0.1.$(git -C "$root" rev-list --count HEAD)}"
repo="rcx24/serverless-aws-tool"   # a PUBLIC repo holding only releases of the tool

echo "Building serverless-aws.cjs ..."
npm install --silent
npm run build

asset="dist/serverless-aws.cjs"
sha="$(shasum -a 256 "$asset" | cut -d' ' -f1)"

echo
echo "Built $asset"
echo "  sha256: $sha"
echo

if command -v gh >/dev/null 2>&1; then
  echo "Publishing release $version to $repo ..."
  gh release create "$version" "$asset" --repo "$repo" --title "$version" \
    --notes "serverless-aws read-only AWS investigation CLI" 2>&1 || \
    gh release upload "$version" "$asset" --repo "$repo" --clobber
  url="https://github.com/$repo/releases/download/$version/serverless-aws.cjs"
else
  echo "gh not found -- upload $asset to a public release yourself."
  url="https://github.com/$repo/releases/download/$version/serverless-aws.cjs"
fi

echo
echo "======================================================================"
echo "Tool catalog entry — paste into the product (Admin -> Tools -> New):"
echo "======================================================================"
cat <<JSON
{
  "key": "serverless-aws",
  "label": "AWS (read-only investigation)",
  "command": "serverless-aws",
  "installKind": "binary",
  "installSpec": { "url": "$url", "sha256": "$sha" },
  "authKind": "none",
  "credentialDelivery": "none"
}
JSON
echo "======================================================================"
echo
echo "Note: authKind is 'none' and credentialDelivery is 'none' because the AWS"
echo "connector delivers ~/.aws/config, not this tool. This entry only puts the"
echo "binary on PATH. The harness gets its credentials from the connector."
