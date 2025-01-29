# Hutia Tests
To get started:
- Install NGINX Unit: https://unit.nginx.org/installation/
- Run `dub test` to run the full test suite

## Writing Tests
Here is a simple sample test:
```D
// This enum prevents having to duplicate the test name.
enum test8 = "hello-world";
@(test8) // unit-threaded will name this test __MODULE__.hello-world
unittest
{
    // Use inNginxUnit for test server code that Unit should invoke.
    if (inNginxUnit())
    {
        // Code here will be run in Unit by Hutia's test runner
        auto app = WebApplication.create();
        app.map!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        // This will run the test server in a dedicated Unit instance.
        // The TestResources returned gives access to the address for
        // the Unit instance.
        auto testResources = runTestAppInUnit(test8, __MODULE__);
        // Be sure to tidy up the Unit instance once done.
        scope(exit) testResources.release();

        // Use an HTTP client to interact with the test server and
        // run asserts against it.
        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) {
            (cast(string)data).shouldEqual("Hello, World!\n");
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200);
        };
        client.perform(ThrowOnError.no);
    }
}
```

## Notes
- To write access logs for a test pass `true` for the `logAccess` parameter of `runTestAppInUnit`.
- This project uses `unit-threaded` which allows:
    - Listing all available tests with `dub test -- --list`
    - Running a single test with `dub test -- test-name`
    - Writing debug output with `dub test -- --debug`
    - See [here](https://code.dlang.org/packages/unit-threaded) for more on the CLI.
- There are cases where running the entire test suite will fail due to port collisions. This is rare and being worked on.