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
            (cast(string)data).shouldEqual(expected, "readToEnd incorrectly read request body");
            return data.length;
        };
        client.perform(ThrowOnError.no);
        client.statusLine().code.shouldEqual(200);
    }
}
