import ballerina/http;
import ballerina/jwt;
import ballerinax/redis;

configurable boolean localDev = true;
configurable string host = ?;
configurable int port = ?;
configurable string password = ?;
configurable string username = ?;

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

        [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(jwtAssertion);
        if !payload.hasKey("email") {
            return <http:Unauthorized> {
                body:  "Email not found in the JWT"
            };
        }
        string email = payload["email"].toString();
        if check isUsageLimitReached(email) {
            return <http:TooManyRequests> {
                body:  "Usage limit reached for the user"
            };
        }
        int _ = check redisClient->incrBy(email, 1);
        return ctx.next();
    }
}

isolated function isUsageLimitReached(string email) returns boolean|error {
    // Check the usage limit for the user
    string? tokenCount = check redisClient->get(email);
    if tokenCount is () {
        string _ = check redisClient->set(email, "0");
        return false;
    }
    int count = check int:fromString(tokenCount);
    if count >= 5 {
        return true;
    }

    return false;
}
