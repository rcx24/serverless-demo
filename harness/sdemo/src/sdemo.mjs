// sdemo -- read-only AWS investigation for the demo harness.
//
// The harness-side companion to the seed CLI's containment logic. It authenticates
// as the read-only investigation role (via ~/.aws/config, which the tool catalog
// wrote), and it cannot read an object or modify a credential -- the same posture
// the runbooks describe. Every subcommand answers one question a runbook asks.

import { readFileSync } from 'node:fs'
import { eventsForKey, keysCreated, accessKeys, identityPolicies, IAM_REGION } from './aws.mjs'

const HOME_REGION = process.env.SDEMO_HOME_REGION || 'us-west-2'
const DISCOVERY_REGIONS = (process.env.SDEMO_DISCOVERY_REGIONS ||
  'ap-northeast-1,eu-central-1,sa-east-1,ap-south-1').split(',')

function allRegions() {
  return [...new Set([HOME_REGION, IAM_REGION, ...DISCOVERY_REGIONS])]
}

function loadArtifact(name) {
  // Runbooks reference runbooks/artifacts/<name>. Look there and in cwd.
  for (const path of [`runbooks/artifacts/${name}`, `artifacts/${name}`, name]) {
    try { return JSON.parse(readFileSync(path, 'utf8')) } catch {}
  }
  throw new Error(`could not find ${name} (looked in runbooks/artifacts/ and .)`)
}

function fail(message) {
  process.stderr.write(`sdemo: ${message}\n`)
  process.exit(1)
}

function arg(argv, name) {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : undefined
}

async function cmdTimeline(argv) {
  const key = arg(argv, 'access-key') || loadArtifact('alert.json').entity?.accessKeyId
  if (!key) fail('no access key given and none in alert.json')
  const since = new Date(arg(argv, 'since') || Date.now() - 2 * 3600 * 1000)

  const events = await eventsForKey(key, allRegions(), since)
  if (!events.length) { console.log('No events for that key in the window.'); return }

  console.log(`Timeline for ${key} (${events.length} events)\n`)
  const regions = new Set()
  let sourceIp = ''
  for (const e of events) {
    regions.add(e.awsRegion)
    sourceIp = sourceIp || (e.sourceIPAddress?.includes('amazonaws.com') ? '' : e.sourceIPAddress)
    console.log(`  ${e.eventTime}  ${e.awsRegion.padEnd(15)} ${e.eventName}`)
  }
  const unusual = [...regions].filter(r => DISCOVERY_REGIONS.includes(r))
  console.log('')
  if (sourceIp) console.log(`  source address: ${sourceIp}`)
  if (unusual.length) console.log(`  cross-region discovery in unused regions: ${unusual.join(', ')}`)
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
  for (const k of keys) console.log(`    ${k.id}  ${k.status}  created ${k.created?.toISOString?.() ?? k.created}`)
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

  const since = new Date(arg(argv, 'since') || Date.now() - 2 * 3600 * 1000)

  // Confirm the half the SOAR claims.
  const compromisedKeys = await accessKeys(compromised)
  const originalDisabled = compromisedKeys.some(k => k.id === compromisedKey && k.status === 'Inactive')
  const policies = await identityPolicies(compromised)
  const quarantined = policies.some(p => p.toLowerCase().includes('quarantine'))

  // Derive what it missed: keys the compromised key created that the SOAR never named.
  const events = await eventsForKey(compromisedKey, allRegions(), since)
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
  if (orphans.length) {
    console.log(`${orphans.length} uncontained key(s). The automation reported containment and missed this.`)
    process.exitCode = 0
  } else {
    console.log('No uncontained keys found.')
  }
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

const HELP = `sdemo -- read-only AWS investigation

  sdemo timeline [--access-key AKIA... | from alert.json] [--since ISO]
  sdemo identity --name <user> [--expand]
  sdemo containment-check [--since ISO]
  sdemo iocs

Authenticates as the read-only investigation role. Cannot read S3 objects or
modify credentials -- if you need either, that is a finding, not an action.`

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
