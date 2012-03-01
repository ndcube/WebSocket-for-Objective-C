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


static const NSInteger WSBufferSize = 1024;
static const NSInteger WSNonceSize = 16;
static const NSInteger WSPort = 80;
static const NSInteger WSPortSecure = 443;
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
static NSString *const WSSecWebSocketProtocolClient = @"Sec-WebSocket-Protocol-Client";
static NSString *const WSSecWebSocketProtocolServer = @"Sec-WebSocket-Protocol-Server";
static NSString *const WSSecWebSocketVersion = @"Sec-WebSocket-Version";
static NSString *const WSSecWebSocketVersionClient = @"Sec-WebSocket-Version-Client";
static NSString *const WSSecWebSocketVersionServer = @"Sec-WebSocket-Version-Server";

static NSString *const WSHTTPCode101 = @"101";


typedef enum {
    WSWebSocketStateNone = 0,
    WSWebSocketStateConnencting = 1,
    WSWebSocketStateOpen = 2,
    WSWebSocketStateClosing = 3,
    WSWebSocketStateClosed = 4
}WSWebSocketStateType;


@implementation WSWebSocket {
    NSURL *serverURL;
    NSInputStream *inputStream;
    NSOutputStream *outputStream;
    
    NSMutableData *dataReceived;
    NSMutableData *dataToSend;
    NSInteger bytesRead;
    NSInteger bytesSent;
    
    BOOL hasSpaceAvailable;
    
    NSMutableArray *datasReceived;
    NSMutableArray *datasToSend;
    
    WSWebSocketStateType state;
    NSString *acceptKey;
}


#pragma mark - Object lifecycle


- (id)initWithUrl:(NSURL *)url {
    self = [super init];
    if (self) {
        datasReceived = [[NSMutableArray alloc] init];
        datasToSend = [[NSMutableArray alloc] init];
        [self analyzeURL:url];
        serverURL = url;
    }
    return self;
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
    unsigned char nonce[WSNonceSize];
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
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)serverURL.host, WSPort, &readStream, &writeStream);
    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;
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
}

- (void)readFromStream {
    if(!dataReceived) {
        dataReceived = [[NSMutableData alloc] init];
    }
    
    uint8_t buffer[WSBufferSize];
    NSInteger length = 0;
    
    length = [inputStream read:buffer maxLength:WSBufferSize];
    
    if (length > 0) {
        [dataReceived appendBytes:(const void *)buffer length:length];
        bytesRead += length;
        NSLog(@"bytesRead: %d", bytesRead);
    }
    else {
        NSLog(@"Read error!");
    }
    
    if (bytesRead < WSBufferSize) {
        [self didReceiveData];
    }
}

- (void)writeToStream {
    
    hasSpaceAvailable = YES;
    
    if (!dataToSend) {
        return;
    }
    
    uint8_t *dataBytes = (uint8_t *)[dataToSend mutableBytes];
    dataBytes += bytesSent;
    unsigned int length = (dataToSend.length - bytesSent) % WSBufferSize;
    uint8_t buffer[length];
    (void)memcpy(buffer, dataBytes, length);
    length = [outputStream write:buffer maxLength:length];
    
    if (length > 0) {
        bytesSent += length;
        
        if (bytesSent >= dataToSend.length) {
            [self didSendData];
        }
    }
    else {
        NSLog(@"Write error!");
    }
    
    hasSpaceAvailable = NO;

}

- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
    NSLog(@"Event code: %d", eventCode);
    
    switch (eventCode) {
        case NSStreamEventOpenCompleted:
            NSLog(@"Opened :%@", aStream);
            break;
        case NSStreamEventHasBytesAvailable:            
            NSLog(@"Bytes available");

            [self readFromStream];

            if (aStream != inputStream) {
                NSLog(@"HEY - output has bytes available?");
            }
            break;
        case NSStreamEventHasSpaceAvailable:            
            NSLog(@"Space available");
            
            [self writeToStream];
            
            if (aStream != outputStream) {
                NSLog(@"HEY - input has space available?");
            }
            break;
        case NSStreamEventErrorOccurred:
            NSLog(@"Status: %d", aStream.streamStatus);
            NSLog(@"Error: %@", aStream.streamError);
            break;
        case NSStreamEventEndEncountered:
            NSLog(@"Closed :%@", aStream);
            [self close];
            break;
        default:
            NSLog(@"Unknown event");
            break;
    }
}


#pragma mark - Handshake


- (void)sendOpeningHandshake {
    
    NSString *nonce = [self nonce];
    NSString *path = serverURL.path.length ? serverURL.path : @"/";
    
    NSString *handshake = [NSString stringWithFormat:
                           @"%@ %@ %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n\r\n",
                           WSGet, path, WSHTTP11,
                           WSHost, serverURL.host,
                           WSUpgrade, WSUpgradeValue,
                           WSConnection, WSConnectionValue,
                           WSSecWebSocketVersion, WSVersion,
                           WSSecWebSocketKey, nonce];
    
    dataToSend = [NSMutableData dataWithData:[handshake dataUsingEncoding:NSUTF8StringEncoding]];
    acceptKey = [self acceptKeyFromNonce:nonce];
    
    NSLog(@"%@", handshake);
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
    NSLog(@"Data received: %@", handshake);
    
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


#pragma mark - Events


- (void)didReceiveResponseForOpeningHandshake {
    NSData *handshakeData = [datasReceived objectAtIndex:0];
    [datasReceived removeObjectAtIndex:0];
    
    if ([self isValidHandshake:[[NSString alloc] initWithData:handshakeData encoding:NSUTF8StringEncoding]]) {
        state = WSWebSocketStateOpen;
        NSLog(@"WebSocket State Open");
    }
    else {
        [self close];
    }
}

- (void)didSendData {
    dataToSend = nil;
    
    if (datasToSend.count) {
        dataToSend = [datasToSend objectAtIndex:0];
        [datasToSend removeObjectAtIndex:0];
    }   
}

- (void)didReceiveData {
    [datasReceived addObject:dataReceived];
    dataReceived = nil;
    
    if (state == WSWebSocketStateConnencting) {
        [self didReceiveResponseForOpeningHandshake];
    }
}


#pragma mark - Public interface


- (void)open {
    state = WSWebSocketStateConnencting;
    [self initiateConnection];
    [self sendOpeningHandshake];
}

- (void)close {
    [self closeConnection];
    state = WSWebSocketStateClosed;
    NSLog(@"WebSocket State Closed");
}

- (void)sendData:(NSData *)data {
    [datasToSend addObject:[NSMutableData dataWithData:data]];
}

- (void)sendText:(NSString *)text {
    [self sendData:[text dataUsingEncoding:NSUTF8StringEncoding]];
}


@end
