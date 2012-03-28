WSWebSocket is a websocket client implementation based on the latest standard [RFC 6455][RFC]. Licensed under the MIT license.

Tested with [Autobahn WebSockets Protocol Test Suite][Autobahn].  
**Current results are:**

**Total 291 tests**

- 279 Pass  
- 12 Non-Strict  
- 0 Fail  
- All clean  

**It is still under development. Use at your own risk.**

Currently does not support:

- Extensions
- Proxy

Handling authentication, setting cookies are left to the user through the corresponding response callback and sendRequest method.


[Autobahn]: http://www.tavendo.de/autobahn/testsuite.html
[RFC]: http://tools.ietf.org/html/rfc6455
