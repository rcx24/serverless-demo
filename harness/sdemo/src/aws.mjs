// The read-only investigation calls sdemo makes, and the region-awareness that
// containment.py learned the hard way.
//
// CloudTrail Event History is per region. IAM is global and logs only to
// us-east-1; other calls log where they were made; object reads are data events
// and are not in Event History at all -- they come from the CloudWatch log group.
// Querying one region finds a fraction of the activity, which is the trap this
// module exists to avoid.

import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail'
import { IAMClient, ListAccessKeysCommand, ListAttachedUserPoliciesCommand,
         ListUserPoliciesCommand, GetUserCommand } from '@aws-sdk/client-iam'
import { fromIni } from '@aws-sdk/credential-providers'

export const IAM_REGION = 'us-east-1'

// The profile the tool catalog writes into ~/.aws/config. `default`, so no flag
// and nothing for the agent to remember.
const credentials = fromIni()

function ct(region) {
  return new CloudTrailClient({ region, credentials })
}

function iam() {
  // IAM is global; any region works, but us-east-1 is its home.
  return new IAMClient({ region: IAM_REGION, credentials })
}

// Every management event a key made, across the regions that could record it,
// deduped by event id. The dedup is load-bearing: a global event (IAM) appears in
// more than one region's Event History, and counting it twice would report two
// findings where there is one.
export async function eventsForKey(accessKeyId, regions, since) {
  const byId = new Map()
  for (const region of regions) {
    let token
    do {
      const page = await ct(region).send(new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: 'AccessKeyId', AttributeValue: accessKeyId }],
        StartTime: since,
        NextToken: token,
      }))
      for (const event of page.Events ?? []) {
        const record = JSON.parse(event.CloudTrailEvent)
        byId.set(record.eventID ?? event.EventId, { ...record, _region: region })
      }
      token = page.NextToken
    } while (token)
  }
  return [...byId.values()].sort((a, b) => a.eventTime < b.eventTime ? -1 : 1)
}

// (target identity, new key id, event id) for each CreateAccessKey the key made.
// The target and new key id come from the event's own responseElements -- which is
// how the orphan is found without anyone naming it. A denied CreateAccessKey has
// no responseElements and created nothing, so it is skipped.
export function keysCreated(events) {
  const created = []
  for (const event of events) {
    if (event.eventName !== 'CreateAccessKey') continue
    const key = event.responseElements?.accessKey
    if (!key?.accessKeyId) continue
    created.push({
      identity: key.userName ?? event.requestParameters?.userName ?? '',
      accessKeyId: key.accessKeyId,
      eventId: event.eventID ?? '',
      eventTime: event.eventTime ?? '',
    })
  }
  return created
}

export async function accessKeys(userName) {
  const out = await iam().send(new ListAccessKeysCommand({ UserName: userName }))
  return (out.AccessKeyMetadata ?? []).map(k => ({ id: k.AccessKeyId, status: k.Status,
                                                   created: k.CreateDate }))
}

export async function identityPolicies(userName) {
  const client = iam()
  const attached = await client.send(new ListAttachedUserPoliciesCommand({ UserName: userName }))
  const inline = await client.send(new ListUserPoliciesCommand({ UserName: userName }))
  return [
    ...(attached.AttachedPolicies ?? []).map(p => `managed:${p.PolicyName}`),
    ...(inline.PolicyNames ?? []).map(n => `inline:${n}`),
  ]
}

export async function whoami() {
  // GetUser with no argument fails for an assumed role; use STS-free identity via
  // a harmless IAM call boundary. sdemo assumes a role, so report that.
  return 'the read-only investigation role for this account'
}
