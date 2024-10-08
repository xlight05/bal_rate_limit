import ballerina/http;

service http:InterceptableService / on new http:Listener(9090) {

    public function createInterceptors() returns RequestInterceptor {
        return new RequestInterceptor();
    }
    resource function get greeting(string? name) returns string|error {
        // Send a response back to the caller.
        if name is () {
            return error("name should not be empty!");
        }
        return string `Hello, ${name}`;
    }
}
