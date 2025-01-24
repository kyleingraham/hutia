import core.runtime : Runtime;
import std.algorithm.searching : canFind;
import std.conv : to;
import std.file : thisExePath;
import std.format : format;
import std.json : parseJSON;
import std.process: kill, pipeProcess, Pid, Redirect, tryWait, wait;
import std.range : back;
import std.socket :TcpSocket, InternetAddress;
import std.stdio : writeln;
import unit_threaded;
import vibe.http.client : requestHTTP;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;

mixin runTestsMain!(
    __MODULE__,
    "routing",
    "handlers",
);

bool inNginxUnit()
{
    auto rt = Runtime();
    return rt.args.canFind(IN_NGINX_UNIT);
}

enum NGINX_UNIT_DUMMY_TEST = "in-nginx-unit";
enum IN_NGINX_UNIT = NGINX_UNIT_DUMMY_TEST;

TestResources runTestAppInUnit(string testName, string testModule, bool logAccess = false)
{
    import std.path : absolutePath, buildPath, dirName;
    TestResources testResources = startUnit();

    try
    {
        string unitConfigTemplate = `{
    "listeners": {
        "127.0.0.1:%s": {
            "pass": "applications/%s"
        }
    },
    "applications": {
        "%s": {
            "type": "external",
            "executable": "%s",
            "arguments": [
                "--single",
                "--debug",
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
            testResources.serverPort(), // application port
            testName, // application name
            testName, // application name
            thisExePath(), // executable name
            IN_NGINX_UNIT, // flag that we running in Nginx Unit
            testModule ~ "." ~ testName, // unit-threaded prefixes name with test's module
            accessLogConfig
        );
        writeln("Unit config: ", unitConfig);

        requestHTTP(
            "http://" ~ testResources.controlAddress() ~ "/config",
            (scope req) {
                auto jsonValue = parseJSON(unitConfig);
                writeln("jsonValue: ", jsonValue);
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
        writeln("Error during request: ", e.msg);
        testResources.release();
        throw e;
    }

    return testResources;
}

TestResources startUnit()
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
    foreach (line; pipe.stdout.byLine)
    {
        output ~= line.idup;
        if (output.back.canFind("started"))
            break;

        if (output.back.canFind("Address already in use"))
            throw new Exception(
                "Unit control address already in use: " ~ testResources.controlAddress()
            );
    }

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

class TestResources
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

    string serverPort()
    {
        return server.toPortString();
    }

    string controlAddress()
    {
        return control.toString();
    }

    void release()
    {
        if (!inNginxUnit() && unitInstance !is null)
        {
            scope(exit) unitInstance.wait();
            writeln("Shutting down Unit...");
            unitInstance.kill();
        }
    }
}

InternetAddress getLocalAddress() {
    auto socket = new TcpSocket();

    // Bind the socket to port 0 (OS will pick an available port)
    socket.bind(new InternetAddress("127.0.0.1", 0));

    auto assignedPort = to!ushort(socket.localAddress.toPortString());
    auto address = new InternetAddress("127.0.0.1", assignedPort);

    socket.close();

    return address;
}
