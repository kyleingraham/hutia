import core.runtime : Runtime;
import std.algorithm.searching : canFind;
import std.conv : to;
import std.file : exists, read, thisExePath, write;
import std.format : format;
import std.json : parseJSON;
import std.process: kill, pipeProcess, Pid, Redirect, tryWait, wait;
import std.range : back;
import std.regex : matchFirst;
import std.socket : InternetAddress;
import std.stdio : writeln;
import std.string : split;
import unit_threaded;
import vibe.http.client : requestHTTP;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;
import std.file : exists, read, write;

mixin runTestsMain!(
    __MODULE__,
    "routing",
    "handlers",
);

bool inNginxUnit() @safe
{
    auto rt = Runtime();
    return (() @trusted => rt.args.canFind(InNginxUnit))();
}

enum InNginxUnit = "in-nginx-unit";

TestResources runTestAppInUnit(
    string testName,
    string testModule,
    bool logAccess = false
) @safe
{
    import std.path : absolutePath, buildPath, dirName;
    TestResources testResources = startUnit();

    try
    {
        string unitConfigTemplate = `{
    "listeners": {
        "%s": {
            "pass": "applications/%s"
        }
    },
    "applications": {
        "%s": {
            "type": "external",
            "executable": "%s",
            "arguments": [
                "--single",
                "%s",
                "%s"
            ],
            "processes": 1
        }
    },
    %s
}`;
        string accessLogConfig;
        if (logAccess)
        {
            auto accessLogConfigTemplate = "\"access_log\": \"" ~ buildPath(
                thisExePath().dirName.absolutePath,
                "logs",
                "%s.log"
            ) ~ "\"";
            accessLogConfig = format(accessLogConfigTemplate, testName);
        }
        string unitConfig = format(
            unitConfigTemplate,
            testResources.serverAddress(), // application port
            testName, // application name
            testName, // application name
            thisExePath(), // executable name
            InNginxUnit, // flag that we running in Nginx Unit
            testModule ~ "." ~ testName, // unit-threaded prefixes name with test's module
            accessLogConfig
        );
        writeln("Unit config: ", unitConfig);
        writeln("Sending config to ", testResources.controlAddress(), "...");
        // TODO: Switch to std.net.curl
        requestHTTP(
            "http://" ~ testResources.controlAddress() ~ "/config",
            (scope req) {
                auto jsonValue = parseJSON(unitConfig);
                req.method = HTTPMethod.PUT;
                req.writeJsonBody(jsonValue);
            },
            (scope res) {
                assert(
                    200 == res.statusCode,
                    format(
                        "Reconfiguration failed (status: %s): %s",
                        res.statusCode,
                        res.bodyReader.readAllUTF8()
                    )
                );
            }
        );
    }
    catch (Exception e)
    {
        writeln("Error while configuring Unit: ", e.msg);
        testResources.release();
        throw e;
    }

    return testResources;
}

TestResources startUnit() @safe
{
    if (inNginxUnit())
        throw new Exception("Cannot start Unit while in Unit");

    auto testResources = new TestResources();
    scope(failure) testResources.release();

    writeln("Starting Unit...");
    auto pipe = pipeProcess(
        ["unitd", "--no-daemon", "--control", testResources.controlAddress()],
        Redirect.stdout | Redirect.stderrToStdout
    );

    string[] output;
    (() @trusted {
        foreach (line; pipe.stdout.byLine) // Resists @aafe
        {
            output ~= line.idup;
            if (output.back.canFind("started"))
                break;

            if (output.back.canFind("Address already in use"))
                throw new Exception(
                    "Unit control address already in use: " ~ testResources.controlAddress()
                );
        }
    })();

    auto pipeWait = pipe.pid.tryWait();
    if (pipeWait.terminated)
    {
        writeln("Unit terminated unexpectedly with code: ", pipeWait.status);
        writeln("Output before termindation: ");
        foreach (line; output)
            writeln(line);

        throw new Exception("Failed to start Unit");
    }

    testResources.unitInstance = pipe.pid;

    writeln("Unit started");
    return testResources;
}

void resetUnitConfig(TestResources testResources) @safe
{
    writeln("Sending reset config to ", testResources.controlAddress(), "...");
    // TODO: Switch to std.net.curl
    requestHTTP(
        "http://" ~ testResources.controlAddress() ~ "/config",
        (scope req) {
            auto jsonValue = parseJSON("{}");
            req.method = HTTPMethod.PUT;
            req.writeJsonBody(jsonValue);
        },
        (scope res) {
            assert(
                200 == res.statusCode,
                format(
                    "Reconfiguration failed (status: %s): %s",
                    res.statusCode,
                    res.bodyReader.readAllUTF8()
                )
            );
        }
    );
}

@safe class TestResources
{
    Pid unitInstance;
    InternetAddress server;
    InternetAddress control;

    this()
    {
        server = getLocalAddress();
        control = getLocalAddress();
    }

    string serverAddress()
    {
        return server.toString();
    }

    string controlAddress()
    {
        return control.toString();
    }

    void release()
    {
        if (inNginxUnit() || unitInstance is null)
            return;

        scope(exit) unitInstance.wait();
        resetUnitConfig(this);
        writeln("Shutting down Unit...");
        (() @trusted => unitInstance.kill())();
    }
}

InternetAddress getLocalAddress() @safe
{
    synchronized {
        InternetAddress current = initializeState();

        auto parts = current.toString().split(":");
        auto addressIndex = parts[0].split(".")[3].to!uint;
        auto port = parts[1].to!uint;

        port = port + 10;
        if (port > MaxPort)
            port = StartPort;

        auto next = new InternetAddress(
            format("127.0.0.%d", addressIndex),
            cast(ushort)port
        );
        writeln("Next address: ", next.toString());

        saveState(next);

        return next;
    }
}

private InternetAddress initializeState() @safe
{
    if (LastAddressFile.exists())
    {
        auto data = (() @trusted => LastAddressFile.read().to!string())();
        auto match = data.matchFirst(r"^127\.0\.0\.(\d+):(\d+)$");
        if (match)
        {
            auto address = format("127.0.0.%s", match.captures[1]);
            auto port = match.captures[2].to!ushort;
            return new InternetAddress(address, port);
        }
    }

    return new InternetAddress(format("127.0.0.%s", LoopbackStart), StartPort);
}

enum LastAddressFile = "hutia-tests-last-address.txt";
enum StartPort = 49152; // Dynamic ports start
enum MaxPort = 65535; // Dynamic ports end
enum LoopbackStart = 1;

private void saveState(InternetAddress state) @safe
{
    LastAddressFile.write(state.toString());
}
