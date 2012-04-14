WSWebSocket is a websocket client implementation based on the latest standard [RFC 6455][RFC]. Licensed under the MIT license.

Tested with [Autobahn WebSockets Protocol Test Suite][Autobahn].  

**Total 291 tests**

- 279 Pass  
- 12 Non-Strict  
- 0 Fail  
- All clean  

**It is still under development.**

Currently does not support:

- Extensions
- Proxy

Handling authentication, setting cookies are left to the user through the corresponding response callback and sendRequest method.

Projects using this library should be linked against the following frameworks: **CFNetwork**, **Security**

**Example of usage**

    NSURL *url = [NSURL URLWithString:@"ws://echo.websocket.org"];
    WSWebSocket *webSocket = [[WSWebSocket alloc] initWithURL:url protocols:nil];

    [webSocket setTextCallback:^(NSString *text) {
        NSLog(@"%@", text);
    }];
    
    [webSocket open];
    [webSocket sendText:@"Hello!"];



[Autobahn]: http://www.tavendo.de/autobahn/testsuite.html
[RFC]: http://tools.ietf.org/html/rfc6455
