import hutia : HttpContext, logError, FromRoute, WebApplication;
import std.array : Appender;
import std.format : format;
import std.random : uniform;
import std.utf : UTFException;
import vibe.stream.operations : readAllUTF8;

int main(string[] args) @safe
{
    auto app = WebApplication.create();
    app.mapGet!simpleHandler("/");
    app.mapGet!parameterBindingHandler("/parameter-binding/{name}/{age:int}/");
    app.mapGet!useContextHandler("/use-context/");
    return app.run();
}

string simpleHandler() @safe
{
    return "Hello, World!\n";
}

string parameterBindingHandler(
    @FromRoute() string name,
    @FromRoute("age") int ageInYears
) @safe
{
    return (() @trusted => format(
        "Received name of type `%s` with value '%s' and age of type `%s` with value '%s'!\n",
        typeof(name).stringof,
        name,
        typeof(ageInYears).stringof,
        ageInYears
    ))();
}

string useContextHandler(HttpContext httpContext) @safe
{
    auto httpRequest = httpContext.request;

    try
    {
        auto requestBody = httpRequest.body.readAllUTF8();
    } catch (UTFException e) {
        auto message = (() @trusted => format("handler - %s", e))();
        // D's standard library logger locks Unit. Looks to cause busy-waiting.
        logError(httpContext, message);
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

    debug(Concurrency)
    {
        import core.time : Duration, msecs;
        import vibe.core.core : sleep;

        Duration randomDuration(int min = 50, int max = 150) @safe
        {
            return uniform(min, max).msecs;
        }

        sleep(randomDuration);
    }

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
