import ballerina/http;
import ballerina/jwt;
import ballerina/io;

configurable boolean localDev = true;

isolated int count = 0 ;

service class RequestInterceptor {
    *http:RequestInterceptor;
    isolated resource function 'default [string... path](http:RequestContext ctx, @http:Header {name: "x-jwt-assertion"} string? jwtAssertion)
        returns http:TooManyRequests|http:Unauthorized| http:NextService|error? {

        if localDev {
            return ctx.next();
        }

        if jwtAssertion is () {
            return <http:Unauthorized> {
            };
        }

        [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(jwtAssertion);
        string email = payload["email"].toString();
        io:println("User Email: " + email);
        if isUsageLimitReached(email) {
            return <http:TooManyRequests> {
                body:  "Usage limit reached for the user"
            };
        }
        lock {
            count = count + 1;
        }
        return ctx.next();
    }
}

isolated function isUsageLimitReached(string email) returns boolean {
    // Check the usage limit for the user
    lock {
        if count > 5 {
            return true;
        }
    }
    return false;
}
