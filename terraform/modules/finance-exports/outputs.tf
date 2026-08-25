output "bucket_name" {
  value = local.bucket_name
}

output "bucket_arn" {
  description = "Known at plan time rather than read back off the resource, which is what lets the read-only role's Deny on this bucket be asserted in CI instead of at apply."
  value       = local.bucket_arn
}

output "object_keys" {
  description = "Every object the bucket holds. The seed picks two or three to read, and the answer key records which -- so a rehearsal can check the analyst found the right ones."
  value       = sort(keys(local.exports))
}
