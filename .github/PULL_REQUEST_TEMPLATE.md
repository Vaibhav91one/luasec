Closes #

## What this changes

## Behavior added or changed

State it as observable behavior, e.g. "a file whose command string is fully
constant is no longer reported".

## Test evidence

```
$ make test
...
```

- [ ] `make test` passes
- [ ] `make tdd-proof BASE HEAD` shows the new tests failing without this change
- [ ] new warning codes have a `docs/rules.md` row, a firing and a silent fixture
- [ ] `vendor/` untouched (`make vendor-verify`)
- [ ] no `os.execute` / `io.popen` in our own source outside the validator driver
