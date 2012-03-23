//
//  WSWebSocket.m
//  WSWebSocket
//
//  Created by Andras Koczka on 2/7/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "WSWebSocket.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#import "NSString+Base64.h"
#import "WSFrame.h"
#import "WSMessage.h"
#import "WSMessageProcessor.h"


static const NSUInteger WSNonceSize = 16;
static const NSUInteger WSPort = 80;
static const NSUInteger WSPortSecure = 443;
static NSString *const WSAcceptGUID = @"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static NSString *const WSScheme = @"ws";
static NSString *const WSSchemeSecure = @"wss";

static NSString *const WSConnection = @"Connection";
static NSString *const WSConnectionValue = @"Upgrade";
static NSString *const WSGet = @"GET";
static NSString *const WSHost = @"Host";
static NSString *const WSHTTP11 = @"HTTP/1.1";
static NSString *const WSOrigin = @"Origin";
static NSString *const WSUpgrade = @"Upgrade";
static NSString *const WSUpgradeValue = @"websocket";
static NSString *const WSVersion = @"13";

static NSString *const WSSecWebSocketAccept = @"Sec-WebSocket-Accept";
static NSString *const WSSecWebSocketExtensions = @"Sec-WebSocket-Extensions";
static NSString *const WSSecWebSocketKey = @"Sec-WebSocket-Key";
static NSString *const WSSecWebSocketProtocol = @"Sec-WebSocket-Protocol";
static NSString *const WSSecWebSocketVersion = @"Sec-WebSocket-Version";

static NSString *const WSHTTPCode101 = @"101";


typedef enum {
    WSWebSocketStateNone = 0,
    WSWebSocketStateConnecting = 1,
    WSWebSocketStateOpen = 2,
    WSWebSocketStateClosing = 3,
    WSWebSocketStateClosed = 4
}WSWebSocketStateType;


@implementation WSWebSocket {
    NSInputStream *inputStream;
    NSOutputStream *outputStream;
    BOOL hasSpaceAvailable;
    
    NSMutableData *dataReceived;
    NSData *dataToSend;
    NSInteger bytesSent;

    WSWebSocketStateType state;
    NSString *acceptKey;

    NSThread *wsThread;
    dispatch_queue_t callbackQueue;
    void (^dataCallback)(NSData *data);
    void (^textCallback)(NSString *text);
    void (^pongCallback)(void);
    void (^closeCallback)(NSUInteger statusCode, NSString *message);

    WSMessageProcessor *messageProcessor;    
    WSFrame *currentFrame;
    uint16_t statusCode;
    NSString *closingReason;
}


@synthesize fragmentSize;
@synthesize hostURL;

- (void)setFragmentSize:(NSUInteger)aFragmentSize {
    fragmentSize = aFragmentSize;
    
    if (fragmentSize < 131) {
        fragmentSize = 131;
    }

    messageProcessor.fragmentSize = fragmentSize;
}


#pragma mark - Object lifecycle


- (id)initWithURL:(NSURL *)url {
    self = [super init];
    if (self) {
        [self analyzeURL:url];
        hostURL = url;
        messageProcessor = [[WSMessageProcessor alloc] init];
        self.fragmentSize = NSUIntegerMax;
        callbackQueue = dispatch_queue_create("WebSocket callback queue", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    dispatch_release(callbackQueue);
}


#pragma mark - Callbacks


- (void)setDataCallback:(void (^)(NSData *data))aDataCallback {
    dataCallback = aDataCallback;
}

- (void)setTextCallback:(void (^)(NSString *text))aTextCallback {
    textCallback = aTextCallback;
}

- (void)setPongCallback:(void (^)(void))aPongCallback {
    pongCallback = aPongCallback;
}

- (void)setCloseCallback:(void (^)(NSUInteger statusCode, NSString *message))aCloseCallback {
    closeCallback = aCloseCallback;
}


#pragma mark - Helper methods


- (void)analyzeURL:(NSURL *)url {
    NSAssert(url.scheme, @"Incorrect URL. Unable to determine scheme from URL: %@", url);
    NSAssert(url.host, @"Incorrect URL. Unable to determine host from URL: %@", url);
}

- (NSData *)SHA1DigestOfString:(NSString *)aString {
    NSData *data = [aString dataUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, data.length, digest);
    
    return [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
}

- (NSString *)nonce {
    uint8_t nonce[WSNonceSize];
    SecRandomCopyBytes(kSecRandomDefault, WSNonceSize, nonce);
    return [NSString encodeBase64WithData:[NSData dataWithBytes:nonce length:WSNonceSize]];
}

- (NSString *)acceptKeyFromNonce:(NSString *)nonce {
    return [NSString encodeBase64WithData:[self SHA1DigestOfString:[nonce stringByAppendingString:WSAcceptGUID]]];    
}


#pragma mark - Data stream


- (void)initiateConnection {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    NSUInteger port = (hostURL.port) ? hostURL.port.integerValue : ([hostURL.scheme.lowercaseString isEqualToString:WSScheme.lowercaseString]) ? WSPort : WSPortSecure;
    
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)hostURL.host, port, &readStream, &writeStream);

    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;

    if ([hostURL.scheme isEqualToString:WSSchemeSecure]) {
        [inputStream setProperty:NSStreamSocketSecurityLevelTLSv1 forKey:NSStreamSocketSecurityLevelKey];
        [outputStream setProperty:NSStreamSocketSecurityLevelTLSv1 forKey:NSStreamSocketSecurityLevelKey];
    }

    inputStream.delegate = self;
    outputStream.delegate = self;
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];    
    [inputStream open];
    [outputStream open];
}

- (void)closeConnection {
    [inputStream close];
    [outputStream close];
    [inputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    inputStream.delegate = nil;
    outputStream.delegate = nil;
    inputStream = nil;
    outputStream = nil;
    state = WSWebSocketStateClosed;

    if (closeCallback) {
        dispatch_async(callbackQueue, ^{
            closeCallback(statusCode, closingReason);
        });
    }
}


#pragma mark - Receive data


- (BOOL)constructMessage {

    if (!dataReceived.length) {
        return NO;
    }
    
    NSUInteger bytesConstructed = messageProcessor.bytesConstructed;
    WSMessage *message = [messageProcessor constructMessageFromData:dataReceived];
        
    // Close frame
    if (message.opcode == WSWebSocketOpcodeClose) {
        [self sendCloseControlFrameWithStatusCode:message.statusCode text:message.text];
    }
    
    // Ping frame
    if (message.opcode == WSWebSocketOpcodePing) {
        WSFrame *frame = [[WSFrame alloc] initWithOpcode:WSWebSocketOpcodePong data:message.data maxSize:fragmentSize];
        [messageProcessor queueFrame:frame];
        [self sendData];
    }
    
    // Pong frame
    if (message.opcode == WSWebSocketOpcodePong && pongCallback) {
        dispatch_async(callbackQueue, ^{
            pongCallback();
        });
    }
    
    // Text message
    if (message.opcode == WSWebSocketOpcodeText && textCallback) {
        
        // Execute the callback block with the constructed message.
        dispatch_async(callbackQueue, ^{
            textCallback(message.text);
        });
    }
    
    // Binary message
    else if (message.opcode == WSWebSocketOpcodeBinary && dataCallback) {

        // Execute the callback block with the constructed message.
        dispatch_async(callbackQueue, ^{
            dataCallback(message.data);
        });
    }

    return bytesConstructed != messageProcessor.bytesConstructed;
}

- (void)readFromStream {
    
    if(!dataReceived) {
        dataReceived = [[NSMutableData alloc] init];
    }
    
    NSUInteger bufferSize = fragmentSize;
    
    // Use a reasonable buffer size
    if (fragmentSize == NSUIntegerMax) {
        bufferSize = 4096;
    }
    
    uint8_t buffer[bufferSize];
    NSInteger length = bufferSize;

    // Read from the stream
    length = [inputStream read:buffer maxLength:bufferSize];

    // Append the bytes read from the stream
    if (length > 0) {
        [dataReceived appendBytes:(const void *)buffer length:length];
    }
    else {
        return;
    }

    if (state == WSWebSocketStateConnecting) {
        
        uint8_t *dataBytes = (uint8_t *)[dataReceived bytes];
        
        // Find end of the header
        for (int i = 0; i < dataReceived.length - 3; i++) {
            if (dataBytes[i] == 0x0d && dataBytes[i + 1] == 0x0a && dataBytes[i + 2] == 0x0d && dataBytes[i + 3] == 0x0a) {
                NSData *handshake = [NSData dataWithBytesNoCopy:dataReceived.mutableBytes length:i + 4 freeWhenDone:NO];
                
                [self didReceiveOpeningHandshakeWithData:handshake];
                
                // Remove the processed handshake data
                if (dataReceived.length == i + 4) {
                    dataReceived = nil;
                }
                // The remaining bytes are preserved
                else {
                    dataBytes += (i + 4);
                    dataReceived = [[NSMutableData alloc] initWithBytes:dataBytes length:dataReceived.length - (i + 4)];
                }
                break;
            }
        }
    }    

    if (state == WSWebSocketStateOpen || state == WSWebSocketStateClosing) {
        
        // Process all the received data or until a partial received fragment is found
        while (messageProcessor.bytesConstructed != dataReceived.length && [self constructMessage]) {
        }
        
        if (messageProcessor.bytesConstructed == dataReceived.length) {
            dataReceived = nil;
            messageProcessor.bytesConstructed = 0;
        }
    }
}


#pragma mark - Send data


- (void)sendCloseControlFrameWithStatusCode:(uint16_t)code text:(NSString *)text {
    
    if (state != WSWebSocketStateOpen) {
        return;
    }
    
    state = WSWebSocketStateClosing;
    
    NSData *messageData = [text dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t length = (code) ? 2 + messageData.length : 0;
    
    NSData *frameData;
    
    // Create the data from the status code and the message
    if (length) {
        
        // Invalid status code
        if (code != 1000 && code != 1001 && code != 1002 && code != 1003 && code != 1007 && code != 1008 && code != 1009 && code != 1010 && code != 1011 && code < 3000) {
            code = 1002;
        }
        
        uint8_t buffer[length];
        uint8_t *payloadData = (uint8_t *)buffer;
        uint16_t *code16 = (uint16_t *)payloadData;
        *code16 = CFSwapInt16HostToBig(code);
        
        statusCode = code;
        
        if (messageData.length) {
            payloadData += 2;
            (void)memcpy(payloadData, messageData.bytes, messageData.length);
            closingReason = text;
        }
        
        frameData = [NSData dataWithBytes:buffer length:length];
    }

    WSFrame *frame = [[WSFrame alloc] initWithOpcode:WSWebSocketOpcodeClose data:frameData maxSize:fragmentSize];
    [messageProcessor queueFrame:frame];
    [self sendData];
}

- (void)sendData {
    if (!hasSpaceAvailable) {
        return;
    }

    if (state == WSWebSocketStateOpen || state == WSWebSocketStateClosing) {

        if (state == WSWebSocketStateOpen) {
            [messageProcessor scheduleNextMessage];
        }
        
        [messageProcessor processMessage];

        if (!dataToSend) {
            currentFrame = [messageProcessor nextFrame];
            dataToSend = currentFrame.data;
        }
    }
    
    [self writeToStream];    
}

- (void)writeToStream {
    if (!dataToSend) {
        return;
    }
    
    uint8_t *dataBytes = (uint8_t *)[dataToSend bytes];
    dataBytes += bytesSent;
    uint64_t length = dataToSend.length - bytesSent;
    
    hasSpaceAvailable = NO;
    length = [outputStream write:dataBytes maxLength:length];
    
    if (length > 0) {
        bytesSent += length;

        // All data has been sent
        if (bytesSent == dataToSend.length) {
            bytesSent = 0;
            dataToSend = nil;
            currentFrame = nil;
        }
    }
}


#pragma mark - NSStreamDelegate


- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
    switch (eventCode) {
        case NSStreamEventOpenCompleted:
            break;
        case NSStreamEventHasBytesAvailable:            
            if (aStream == inputStream) {
                [self readFromStream];
            }
            break;
        case NSStreamEventHasSpaceAvailable:            
            if (aStream == outputStream) {
                hasSpaceAvailable = YES;
                [self sendData];
            }
            break;
        case NSStreamEventErrorOccurred:
            NSLog(@"Error: %@", aStream.streamError);
            break;
        case NSStreamEventEndEncountered:
            [self closeConnection];
            break;
        default:
            NSLog(@"Unknown event");
            break;
    }
}


#pragma mark - Handshake


- (void)sendOpeningHandshake {
    NSString *nonce = [self nonce];
    NSString *pathQuery = (hostURL.query) ? [NSString stringWithFormat:@"%@?%@", hostURL.path, hostURL.query] : hostURL.path.length ? hostURL.path : @"/";
    NSString *hostPort = (hostURL.port) ? [NSString stringWithFormat:@"%@:%@", hostURL.host, hostURL.port] : hostURL.host;
    
    NSString *handshake = [NSString stringWithFormat:
                           @"%@ %@ %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n\r\n",
                           WSGet, pathQuery, WSHTTP11,
                           WSHost, hostPort,
                           WSUpgrade, WSUpgradeValue,
                           WSConnection, WSConnectionValue,
                           WSSecWebSocketVersion, WSVersion,
                           WSSecWebSocketKey, nonce];
    
    dataToSend = [handshake dataUsingEncoding:NSUTF8StringEncoding];
    acceptKey = [self acceptKeyFromNonce:nonce];
}

- (NSInteger)indexOfHeaderField:(NSString *)headerField inComponents:(NSArray *)components {
    NSInteger index = 0;

    for (NSString *component in components) {
        if ([component isEqualToString:[NSString stringWithFormat:@"%@:", headerField]]) {
            return index;
        }
        index++;
    }
    
    return -1;
}

- (BOOL)isValidHandshake:(NSString *)handshake {
    NSArray *components = [handshake componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    if (![[components objectAtIndex:1] isEqualToString:WSHTTPCode101]) {
        return NO;
    }

    NSInteger upgradeIndex = [self indexOfHeaderField:WSUpgrade inComponents:components];
    NSInteger connectionIndex = [self indexOfHeaderField:WSConnection inComponents:components];
    NSInteger acceptIndex = [self indexOfHeaderField:WSSecWebSocketAccept inComponents:components];
    
    if (![[[components objectAtIndex:upgradeIndex + 1] lowercaseString] isEqualToString:WSUpgradeValue.lowercaseString]) {
        return NO;
    }

    if (![[[components objectAtIndex:connectionIndex + 1] lowercaseString] isEqualToString:WSConnectionValue.lowercaseString]) {
        return NO;
    }
    
    if (![[components objectAtIndex:acceptIndex + 1] isEqualToString:acceptKey]) {
        return NO;
    }

    return YES;
}

- (void)didReceiveOpeningHandshakeWithData:(NSData *)handshakeData {
    if ([self isValidHandshake:[[NSString alloc] initWithData:handshakeData encoding:NSUTF8StringEncoding]]) {
        state = WSWebSocketStateOpen;
        [self sendData];
    }
    else {
        [self closeConnection];
    }
}


#pragma mark - Thread


- (void)webSocketThreadLoop {
    @autoreleasepool {
        while (state != WSWebSocketStateClosed) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 4.0, NO);
        }
    }
}


#pragma mark - Threaded methods


- (void)threadedOpen {
    [self initiateConnection];
    [self sendOpeningHandshake];
}

- (void)threadedClose {
    [self sendCloseControlFrameWithStatusCode:1000 text:nil];
}

- (void)threadedSendData:(NSData *)data {
    WSMessage *message = [[WSMessage alloc] init];
    
    message.opcode = WSWebSocketOpcodeBinary;
    message.data = data;

    [messageProcessor queueMessage:message];
    [self sendData];
}

- (void)threadedSendText:(NSString *)text {
    WSMessage *message = [[WSMessage alloc] init];

    message.opcode = WSWebSocketOpcodeText;
    message.text = text;
    
    [messageProcessor queueMessage:message];
    [self sendData];
}

- (void)threadedSendPingWithData:(NSData *)data {
    if (state == WSWebSocketStateConnecting || state == WSWebSocketStateOpen) {
        WSFrame *frame = [[WSFrame alloc] initWithOpcode:WSWebSocketOpcodePing data:data maxSize:fragmentSize];
        [messageProcessor queueFrame:frame];
        [self sendData];
    }
}


#pragma mark - Public interface


- (void)open {
    if (state != WSWebSocketStateNone) {
        return;
    }
    
    state = WSWebSocketStateConnecting;
    
    wsThread = [[NSThread alloc] initWithTarget:self selector:@selector(webSocketThreadLoop) object:nil];
    [wsThread start];
    [self performSelector:@selector(threadedOpen) onThread:wsThread withObject:nil waitUntilDone:NO];
}

- (void)close {
    [self performSelector:@selector(threadedClose) onThread:wsThread withObject:nil waitUntilDone:NO];
}

- (void)sendData:(NSData *)data {
    if (!data) {
        data = [[NSData alloc] init];
    }
    
    [self performSelector:@selector(threadedSendData:) onThread:wsThread withObject:data waitUntilDone:NO];
}

- (void)sendText:(NSString *)text {
    if (!text) {
        text = @"";
    }
    
    [self performSelector:@selector(threadedSendText:) onThread:wsThread withObject:text waitUntilDone:NO];
}

- (void)sendPingWithData:(NSData *)data {
    [self performSelector:@selector(threadedSendPingWithData:) onThread:wsThread withObject:data waitUntilDone:NO];
}

@end
