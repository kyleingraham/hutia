import hutia;
import runner;
import std.net.curl : HTTP, ThrowOnError;
import std.traits : EnumMembers;
import unit_threaded : shouldEqual, ShouldFail;
import vibe.http.client : requestHTTP;
import vibe.http.common : HTTPMethod, HTTPStatusException;
import vibe.stream.operations : readAllUTF8;

enum test1 = "readToEnd-reads-whole-request-body";
@(test1)
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
        auto testResources = runTestAppInUnit(test1, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.post;
        auto expected = "Read to end!\n";
        client.postData = expected;
        client.onReceive = (ubyte[] data) {
            (cast(string)data).shouldEqual(
                expected,
                "readToEnd incorrectly read request body"
            );
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200);
        };
        client.perform(ThrowOnError.no);
    }
}

string fromRouteHandler(@FromRoute() int num) @safe
{
    return "Hello, World!\n";
}

enum test2 = "FromRoute-conversion-error-triggers-500s";
@(test2)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!fromRouteHandler("/{num:int}/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test2, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP(
            "http://" ~ testResources.serverAddress() ~ "/1000000000000000000000000000000/")
        ;
        client.method = HTTP.Method.get;
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(500, "Route succeeded unexpectedly");
        };
        client.perform(ThrowOnError.no);
    }
}

@("FromRoute-incompatible-with-lambdas")
unittest
{
    // In D we don't yet have a way to read parameter names from lambda definitions.
    auto app = WebApplication.create();
    static assert(
        !__traits(
            compiles,
            app.map!((@FromRoute() int num) => "Hello, World!\n")("/{num:int}/")
        )
    );
}

string unsafeHandler() {return "Unsafe";}

string safeHandler() @safe {return "Safe";}

@("Hutia-rejects-unsafe-handlers")
unittest
{
    auto app = WebApplication.create();
    static assert(
        !__traits(compiles, app.map!unsafeHandler("/")),
        "Unsafe handler accepted"
    );
    static assert(
        __traits(compiles, app.map!safeHandler("/")),
        "Safe handler rejected"
    );
}

string noParamsHandler() @safe {return "Hello, World!\n";}

string contextFromRouteHandler(
    HttpContext context,
    @FromRoute() int num
) @safe
{
    return "Hello, World!\n";
}

string multipleFromRouteHandler(
    @FromRoute() int a,
    @FromRoute() int b
) @safe
{
    return "Hello, World!\n";
}

@("Hutia-supports-string-returning-handlers")
unittest
{
    auto app = WebApplication.create();
    static assert(
        __traits(compiles, app.map!noParamsHandler("/"))
    );
    static assert(
        __traits(compiles, app.map!fromRouteHandler("/"))
    );
    static assert(
        __traits(compiles, app.map!contextFromRouteHandler("/"))
    );
    static assert(
        __traits(compiles, app.map!multipleFromRouteHandler("/"))
    );
}

enum test3 = "routeValues-contains-output-from-route-constraints";
@(test3)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!((HttpContext httpContext) {
            auto routeValues = httpContext.request.routeValues;
            return routeValues["name"] ~ " " ~ routeValues["age"];
        })("/{name:string}/{age:int}/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test3, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/hutia/0/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) {
            (cast(string)data).shouldEqual(
                "hutia 0",
                "Did not receive expected route values"
            );
            return data.length;
        };
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200, "Route not matched as expected");
        };
        client.perform(ThrowOnError.no);
    }
}

enum test4 = "vibed-concurrency-works";
@(test4)
unittest
{
    if (inNginxUnit())
    {
        auto app = WebApplication.create();
        app.map!(() {
            import core.time : msecs;
            import vibe.core.core : sleep;

            sleep(1.msecs);
            return "Slept";
        })("/");
        auto rc = app.run();
        assert(rc == 0, "App failed. Check Unit logs for details.");
    }
    else
    {
        auto testResources = runTestAppInUnit(test4, __MODULE__);
        scope(exit) testResources.release();

        auto client = HTTP("http://" ~ testResources.serverAddress() ~ "/");
        client.method = HTTP.Method.get;
        client.onReceive = (ubyte[] data) => data.length;
        client.onReceiveStatusLine = (HTTP.StatusLine statusLine) {
            statusLine.code.shouldEqual(200);
        };
        client.perform(ThrowOnError.no);
    }
}

// TODO:
// Test string is default route constraint -> 911/taycan
// Multiple, 1, no contraints
// Each route constraint
// Call only first matched handler
