// The read-only AWS calls serverless-aws makes, and the region-awareness that is
// easy to get wrong.
//
// CloudTrail Event History is per region. IAM is global and logs only to
// us-east-1 -- a constant, not something to configure. Other calls log where they
// were made; object reads are data events and are not in Event History at all.
// Querying one region finds a fraction of the activity, which is the trap this
// module exists to avoid.
//
// Nothing here needs configuration. The credential comes from ~/.aws/config (which
// a connector writes); the regions to search come from the alert being
// investigated, not from an environment variable somebody has to remember to set.

import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail'
import { IAMClient, ListAccessKeysCommand, ListAttachedUserPoliciesCommand,
         ListUserPoliciesCommand } from '@aws-sdk/client-iam'
import { fromNodeProviderChain } from '@aws-sdk/credential-providers'

// IAM is a global service; its events and its API both resolve through us-east-1
// regardless of where the caller is. A constant, deliberately not configurable --
// making it a setting would only create a way to set it wrong.
export const IAM_REGION = 'us-east-1'

// The default AWS credential chain: ~/.aws/config (what the connector writes),
// then environment, then anything else the SDK knows. No profile to pass.
const credentials = fromNodeProviderChain()

function ct(region) {
  return new CloudTrailClient({ region, credentials })
}

function iam() {
  return new IAMClient({ region: IAM_REGION, credentials })
}

// Every management event a key made, across the given regions, deduped by event
// id. The dedup is load-bearing: a global event (IAM) appears in more than one
// region's Event History, and counting it twice would report two findings where
// there is one.
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
// how a created credential is found without anyone naming the identity in advance.
// A denied CreateAccessKey has no responseElements and created nothing, so it is
// skipped.
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
