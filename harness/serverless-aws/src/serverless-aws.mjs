// serverless-aws -- read-only AWS investigation.
//
// Reads credentials from ~/.aws/config (which the AWS connector writes) and makes
// no changes to anything. Every subcommand answers one question a runbook asks,
// and nothing here needs configuration: the account and the key come from the
// alert being investigated, and the one region that is not obvious (IAM's
// us-east-1) is a constant, not a setting.

import { readFileSync } from 'node:fs'
import { eventsForKey, keysCreated, accessKeys, identityPolicies, IAM_REGION } from './aws.mjs'

// Where the runbooks put the artifacts. Looked up in order; the agent runs from
// the workspace, and the clone lands under it.
const ARTIFACT_DIRS = ['runbooks/artifacts', 'artifacts', '.']

function loadArtifact(name) {
  for (const dir of ARTIFACT_DIRS) {
    try { return JSON.parse(readFileSync(`${dir}/${name}`, 'utf8')) } catch {}
  }
  throw new Error(`could not find ${name} (looked in ${ARTIFACT_DIRS.join(', ')})`)
}

function fail(message) {
  process.stderr.write(`serverless-aws: ${message}\n`)
  process.exit(1)
}

function arg(argv, name) {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : undefined
}

// The regions to search, derived rather than configured. Every region the alert's
// own events touch, plus us-east-1 for the IAM events that log nowhere else. This
// is what removes the SDEMO_DISCOVERY_REGIONS env var: the alert already names the
// regions the attacker used, in its samples.
function regionsFromAlert(alert) {
  const regions = new Set([IAM_REGION])
  for (const sample of alert?.samples ?? []) {
    if (sample.awsRegion) regions.add(sample.awsRegion)
  }
  return [...regions]
}

function windowStart(argv, alert) {
  if (arg(argv, 'since')) return new Date(arg(argv, 'since'))
  // The earliest sampled event, less a margin, so nothing is missed at the edge.
  const times = (alert?.samples ?? []).map(s => new Date(s.eventTime)).filter(d => !isNaN(d))
  if (times.length) return new Date(Math.min(...times) - 30 * 60 * 1000)
  return new Date(Date.now() - 2 * 3600 * 1000)
}

async function cmdTimeline(argv) {
  const alert = safeAlert()
  const key = arg(argv, 'access-key') || alert?.entity?.accessKeyId
  if (!key) fail('no access key given and none in alert.json')
  const regions = arg(argv, 'regions') ? arg(argv, 'regions').split(',') : regionsFromAlert(alert)
  const since = windowStart(argv, alert)

  const events = await eventsForKey(key, regions, since)
  if (!events.length) { console.log('No events for that key in the window.'); return }

  console.log(`Timeline for ${key} (${events.length} events)\n`)
  const seen = new Set()
  let sourceIp = ''
  for (const e of events) {
    seen.add(e.awsRegion)
    if (!sourceIp && e.sourceIPAddress && !e.sourceIPAddress.includes('amazonaws.com')) {
      sourceIp = e.sourceIPAddress
    }
    console.log(`  ${e.eventTime}  ${e.awsRegion.padEnd(15)} ${e.eventName}`)
  }
  console.log('')
  if (sourceIp) console.log(`  source address: ${sourceIp}`)
  const homeGuess = alert?.samples?.find(s => s.eventName === 'GetCallerIdentity')?.awsRegion
  const unusual = [...seen].filter(r => r !== IAM_REGION && r !== homeGuess)
  if (unusual.length) console.log(`  activity in other regions: ${unusual.join(', ')}`)
  const created = keysCreated(events)
  if (created.length) {
    console.log(`  credential creation: ${created.map(c => `${c.accessKeyId} on ${c.identity}`).join(', ')}`)
    console.log('  -> follow this in containment-verification.md')
  }
}

async function cmdIdentity(argv) {
  const name = arg(argv, 'name')
  if (!name) fail('--name <identity> required')
  const keys = await accessKeys(name)
  const policies = await identityPolicies(name)
  console.log(`Identity ${name}\n`)
  console.log('  access keys:')
  for (const k of keys) {
    const created = k.created?.toISOString?.() ?? k.created
    console.log(`    ${k.id}  ${k.status}  created ${created}`)
  }
  if (!keys.length) console.log('    (none)')
  console.log('  policies:')
  for (const p of policies) console.log(`    ${p}`)
  if (!policies.length) console.log('    (none)')
}

async function cmdContainmentCheck(argv) {
  const alert = loadArtifact('alert.json')
  const soarCase = loadArtifact('soar-case.json')
  const compromisedKey = alert.entity?.accessKeyId
  const compromised = alert.entity?.principalArn?.split('/').pop()
  if (!compromisedKey) fail('alert.json has no entity.accessKeyId')
  const since = windowStart(argv, alert)

  // Confirm the half the SOAR claims. All IAM, so region-agnostic.
  const compromisedKeys = await accessKeys(compromised)
  const originalDisabled = compromisedKeys.some(k => k.id === compromisedKey && k.status === 'Inactive')
  const policies = await identityPolicies(compromised)
  const quarantined = policies.some(p => p.toLowerCase().includes('quarantine'))

  // Derive what it missed. CreateAccessKey is an IAM event -> us-east-1 only.
  const events = await eventsForKey(compromisedKey, [IAM_REGION], since)
  const created = keysCreated(events)
  const soarNamed = new Set((soarCase.steps ?? []).map(s => s.target))

  const findings = []
  for (const c of created) {
    const live = await accessKeys(c.identity)
    const match = live.find(k => k.id === c.accessKeyId)
    const status = match?.status ?? 'Unknown'
    const named = soarNamed.has(c.accessKeyId) || soarNamed.has(c.identity)
    findings.push({ ...c, status, named, orphan: status === 'Active' && !named })
  }

  console.log(`Containment verification for ${compromised}\n`)
  console.log(`  SOAR disposition claimed: ${soarCase.disposition ?? 'unknown'}`)
  console.log(`  quarantine policy present: ${quarantined ? 'yes' : 'NO'}`)
  console.log(`  alerting key disabled:     ${originalDisabled ? 'yes' : 'NO'}\n`)
  console.log('  keys the compromised identity created:')
  if (!findings.length) console.log('    (none)')
  for (const f of findings) {
    const flag = f.orphan ? '  <-- UNCONTAINED' : ''
    console.log(`    ${f.identity.padEnd(22)} ${f.accessKeyId}  ${f.status.padEnd(9)} named in case: ${f.named ? 'yes' : 'NO'}${flag}`)
    if (f.orphan) console.log(`        evidence: ${f.eventId}`)
  }
  const orphans = findings.filter(f => f.orphan)
  console.log('')
  console.log(orphans.length
    ? `${orphans.length} uncontained key(s). The automation reported containment and missed this.`
    : 'No uncontained keys found.')
}

async function cmdIocs() {
  const iocs = loadArtifact('iocs.json')
  console.log('Seeded indicators (from the detection):\n')
  for (const [type, entries] of Object.entries(iocs.indicators ?? {})) {
    for (const e of entries) console.log(`  ${type.padEnd(14)} ${e.value}  [${e.disposition}]`)
  }
  console.log('\nAdd what the investigation found -- most importantly the uncontained')
  console.log('access key from containment-verification -- before importing.')
}

function safeAlert() {
  try { return loadArtifact('alert.json') } catch { return null }
}

const HELP = `serverless-aws -- read-only AWS investigation

  serverless-aws timeline [--access-key AKIA... | from alert.json] [--since ISO] [--regions r1,r2]
  serverless-aws identity --name <user>
  serverless-aws containment-check
  serverless-aws iocs

Reads credentials from ~/.aws/config and makes no changes. Nothing to configure --
the account and key come from alert.json, and IAM's region is a constant. If a
call is refused (reading an object, changing a credential), that is a finding to
report, not something to work around.`

async function main() {
  const [cmd, ...rest] = process.argv.slice(2)
  try {
    switch (cmd) {
      case 'timeline': return await cmdTimeline(rest)
      case 'identity': return await cmdIdentity(rest)
      case 'containment-check': return await cmdContainmentCheck(rest)
      case 'iocs': return await cmdIocs()
      case undefined: case '--help': case '-h': console.log(HELP); return
      default: fail(`unknown command "${cmd}". Try --help.`)
    }
  } catch (error) {
    fail(error.message)
  }
}

main()
