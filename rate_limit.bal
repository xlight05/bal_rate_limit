import ballerina/http;
import ballerina/jwt;
import ballerinax/redis;
import ballerina/io;

configurable boolean localDev = true;
configurable string host = ?;
configurable int port = ?;
configurable string password = ?;
configurable string username = ?;
configurable string env = ?;

configurable int MAX_TOKEN_COUNT_PER_USER = 5;

final redis:Client redisClient = check new (
    connection = {
        host: host,
        port: port,
        password: password,
        username: username
    },
    connectionPooling = true,
    secureSocket = {
        verifyMode: redis:NONE
    }
);

service class RequestInterceptor {
    *http:RequestInterceptor;
    isolated resource function 'default [string... path](http:RequestContext ctx, @http:Header {name: "x-jwt-assertion"} string? jwtAssertion)
        returns http:TooManyRequests|http:Unauthorized|http:NextService|error? {

        if localDev {
            return ctx.next();
        }

        // To enable try it mode in choreo.
        if jwtAssertion is () {
            return <http:Unauthorized> {
            };
        }
        io:println(jwtAssertion);

        [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(jwtAssertion);
        string? sub = payload.sub;
        if sub is () {
            return <http:Unauthorized> {
                body:  "Subject not found"
            };
        }

        string redisKey = string `bal-${env}-${sub}`;
        if check isUsageLimitReached(redisKey) {
            return <http:TooManyRequests> {
                body:  "Usage limit reached for the user"
            };
        }
        //TODO: Change based on token usage
        int _ = check redisClient->incrBy(redisKey, 1);
        return ctx.next();
    }
}

isolated function isUsageLimitReached(string id) returns boolean|error {
    // Check the usage limit for the user
    string? tokenCount = check redisClient->get(id);
    if tokenCount is () {
        string _ = check redisClient->set(id, "0");
        return false;
    }
    int count = check int:fromString(tokenCount);
    if count >= MAX_TOKEN_COUNT_PER_USER {
        return true;
    }

    return false;
}
