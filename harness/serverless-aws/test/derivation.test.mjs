// The two properties that make containment-check trustworthy, tested without AWS.
// Mirrors the Python test_containment.py, because serverless-aws and the seed CLI must
// derive the same finding from the same evidence -- if they diverge, the demo the
// harness runs disagrees with the rehearsal that validated it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { keysCreated } from '../src/aws.mjs'

test('a created key is taken from the event responseElements, not named in advance', () => {
  const events = [{
    eventName: 'CreateAccessKey',
    eventID: 'evt-1',
    eventTime: '2026-08-25T02:00:00Z',
    responseElements: { accessKey: { userName: 'svc-report-runner', accessKeyId: 'AKIAORPHAN' } },
  }]
  const created = keysCreated(events)
  assert.equal(created.length, 1)
  assert.equal(created[0].identity, 'svc-report-runner')
  assert.equal(created[0].accessKeyId, 'AKIAORPHAN')
})

test('a denied CreateAccessKey created nothing and yields no finding', () => {
  const events = [{
    eventName: 'CreateAccessKey',
    eventID: 'evt-2',
    errorCode: 'AccessDenied',
    requestParameters: { userName: 'svc-report-runner' },
    // no responseElements -- nothing was created
  }]
  assert.equal(keysCreated(events).length, 0)
})

test('non-create events are ignored', () => {
  const events = [
    { eventName: 'ListUsers', eventID: 'a' },
    { eventName: 'DescribeInstances', eventID: 'b' },
  ]
  assert.equal(keysCreated(events).length, 0)
})
