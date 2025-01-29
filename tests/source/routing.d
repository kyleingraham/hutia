import hutia;
import runner;
import std.conv : to;
import std.net.curl : HTTP, ThrowOnError;
import std.traits : EnumMembers;
import unit_threaded : shouldEqual, shouldThrowWithMessage;

enum test1 = "mapGet-rejects-non-GET-requests";
@(test1)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.mapGet!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test1, __MODULE__);
        scope(exit) testResources.release();

        foreach (method; EnumMembers!(HTTP.Method))
        {
            if (method == HTTP.Method.get || method == HTTP.Method.undefined)
                continue;

            auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
            client.method = method;
            if (method == HTTP.Method.put || method == HTTP.Method.post)
                client.contentLength = 0; // 411 status if omitted

            client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
                statusLine.code.shouldEqual(
                    404,
                    "Non-GET request allowed in mapPost"
                );
            };
            client.perform(ThrowOnError.no);
        }
    }
}

enum test2 = "mapGet-accepts-GET-requests";
@(test2)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.mapGet!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test2, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) {
            (cast(string)data).shouldEqual("Hello, World!\n");
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200, "GET request failed in mapGet");
        };
        client.perform(ThrowOnError.no);
    }
}

enum test3 = "map-accepts-HEAD-requests";
@(test3)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test3, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.head;
        client.onReceive = (ubyte[] data) {
            assert(0, "Received a body for a HEAD request: " ~ cast(string)data);
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200, "HEAD request failed in mapGet");
        };
        client.perform(ThrowOnError.no);
    }
}

enum test4 = "mapPost-accepts-POST-requests";
@(test4)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.mapPost!((HttpContext httpContext) {
            return httpContext.request.body.readToEnd();
        })("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test4, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.post;
        auto expected = "Read to end!\n";
        client.postData = expected;
        client.onReceive = (ubyte[] data) {
            (cast(string)data).shouldEqual(expected, "POST data did not round-trip");
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200);
        };
        client.perform(ThrowOnError.no);
    }
}

enum test5 = "mapPost-rejects-non-POST-requests";
@(test5)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.mapPost!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test5, __MODULE__);
        scope(exit) testResources.release();

        foreach (method; EnumMembers!(HTTP.Method))
        {
            if (method == HTTP.Method.post || method == HTTP.Method.undefined)
                continue;

            auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
            client.method = method;
            if (method == HTTP.Method.put)
                client.contentLength = 0; // 411 status if omitted

            client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
                statusLine.code.shouldEqual(404, "Non-POST request allowed in mapPost");
            };
            client.perform(ThrowOnError.no);
        }
    }
}

enum test6 = "map-accepts-non-CONNECT-TRACE-requests";
@(test6)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test6, __MODULE__);
        scope(exit) testResources.release();

        foreach (method; [
            HTTP.Method.del, HTTP.Method.get, HTTP.Method.head, HTTP.Method.patch,
            HTTP.Method.options, HTTP.Method.post, HTTP.Method.put
        ])
        {
            auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
            client.method = method;
            if (method == HTTP.Method.post || method == HTTP.Method.put)
                client.contentLength = 0; // 411 status if omitted

            client.onReceive = (ubyte[] data) => data.length;
            client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
                statusLine.code.shouldEqual(
                    200,
                    "Non-CONNECT/TRACE request rejected in map: " ~ to!string(method)
                );
            };
            client.perform(ThrowOnError.no);
        }
    }
}

enum test7 = "map-rejects-CONNECT-TRACE-requests";
@(test7)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!(() => "Hello, World!\n")("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test7, __MODULE__);
        scope(exit) testResources.release();

        foreach (method; [HTTP.Method.connect, HTTP.Method.trace])
        {
            auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
            client.method = method;
            client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
                statusLine.code.shouldEqual(
                    404,
                    "CONNECT/TRACE request accepted in map: " ~ to!string(method)
                );
            };
            client.perform(ThrowOnError.no);
        }
    }
}

enum test8 = "route-constraints-influence-route-matching";
@(test8)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!(() => "Hello, World!\n")("/{name}/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test8, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/hutia/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) => data.length;
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200, "Route not matched as expected");
        };
        client.perform(ThrowOnError.no);
        client.statusLine().code.shouldEqual(200, "Route not matched as expected");

        client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) => data.length;
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(404, "Route matched unexpectedly");
        };
        client.perform(ThrowOnError.no);
    }
}

@("unknown-route-contraints-trigger-warnings")
unittest
{
    auto app = WebApplication.create();
    app
    .map!(() => "Hello, World!\n")("/{name:unknown}/")
    .shouldThrowWithMessage!ImproperlyConfigured(
        "Route constraint for `unknown` not found"
    );
}

@("invalid-route-contraints-trigger-warnings")
unittest
{
    auto app = WebApplication.create();
    app
    .map!(() => "Hello, World!\n")("/{this:is:invalid}/")
    .shouldThrowWithMessage!ImproperlyConfigured(
        "Invalid route constraint `{this:is:invalid}`"
    );
}
