# Hutia Tests
To get started:
- Install NGINX Unit: https://unit.nginx.org/installation/
- Run `dub test` to run the full test suite

## Writing Tests


## Notes
- To write access logs for a test pass `true` for the `logAccess` parameter of `runTestAppInUnit`.
- This project uses `unit-threaded` which allows:
    - Listing all available tests with `dub test -- --list`
    - Running a single test with `dub test -- test-name`
    - Writing debug output with `dub test -- --debug`
- There are cases where running the entire test suite will fail due to port collisions. This is rare and being worked on.