# TODO

Author: M00NLIG7

---

## auditd: Streaming Event Correlation for Large Logs

The current `ParseEvents` implementation buffers all records in memory before
grouping them by sequence number. For typical forensic log sizes this is fine,
but multi-gigabyte audit logs (millions of records) will hit memory pressure.

**Problem:** `groups` and `seqOrder` accumulate the entire file before any
sigma evaluation happens. A 1 GB audit log with ~5 M records could easily
consume several GB of RAM after field-map allocation.

**Proposed fix: sliding-window grouping**

auditd guarantees that all records for the same event are written
consecutively. A window of the last N sequence numbers can be kept in memory
and flushed once a new seq is seen that can't belong to the current group:

```go
// Flush a group once we've moved past its seq range.
// Typical burst size is 4-6 records per event so a window of 32 is safe.
const windowSize = 32
```

This would reduce peak memory from O(total records) to O(window × fields),
making multi-GB log scanning practical without changing the public API.

**Checklist**

- [ ] Benchmark memory usage against a large synthetic log (> 100k events)
- [ ] Implement sliding-window grouping in `ParseEvents`
- [ ] Verify ordering is preserved and no events are dropped at window boundaries
- [ ] Add test: window flush does not split a correlated group
