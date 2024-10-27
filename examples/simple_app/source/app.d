import core.time : Duration, msecs;
import hutia : HttpContext, logError, WebApplication;
import std.array : Appender;
import std.format : format;
import std.random : uniform;
import std.utf : UTFException;
import vibe.core.core : sleep;
import vibe.stream.operations : readAllUTF8;

int main(string[] args) @safe
{
    auto app = WebApplication.create();
    return app
           .map("", &handler) // map doesn't do any routing today and only supports setting a single handler app-wide.
           .run();
}

// We need extern(C) here to satisfy an implementation detail of hutia's NGINX Unit integration.
// In a future version this requirement won't be imposed on users.
extern(C)
string handler(HttpContext httpContext) @safe
{
    auto httpRequest = httpContext.request;

    try
    {
        auto requestBody = httpRequest.body.readAllUTF8();
    } catch (UTFException e) {
        auto message = (() @trusted => format("handler - %s", e))();
        logError(httpContext, message); // D's standard library logger locks Unit. Looks to cause busy-waiting.
    }

    auto httpResponse = httpContext.response;
    httpResponse.statusCode = 200;
    httpResponse.headers.addField("Content-Type", "text/html; charset=utf-8");

    Appender!string response;

    response.put(`<!DOCTYPE html>
<html lang="en">
<head></head>
<body>
    <h1>Hello, World!</h1>
    <p>Here are some random strings:</p>
`);

    foreach (_; 0..10)
    {
        response.put(`    <p>` ~ randomString() ~ `</p>
`);
    }

    response.put(`</body>
</html>
`);

    //sleep(randomDuration);

    return response.data;
}

string randomString(uint length = 12) @safe
{
    const char[] charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    Appender!string result;
    
    foreach (_; 0..length)
        result.put(charset[uniform(0, charset.length)]);

    return result.data;
}

Duration randomDuration(int min = 50, int max = 150) @safe
{
    return uniform(min, max).msecs;
}
