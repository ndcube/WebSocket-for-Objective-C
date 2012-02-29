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


static const NSInteger bufferSize = 1024;
static const NSInteger nonceSize = 16;
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


@implementation WSWebSocket {
    NSURL *serverURL;
    NSInputStream *inputStream;
    NSOutputStream *outputStream;
    NSMutableData *dataReceived;
    NSMutableData *dataToSend;
    NSInteger bytesRead;
    NSInteger bytesSent;
    BOOL hasSpaceAvailable;
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
    unsigned char nonce[nonceSize];
    SecRandomCopyBytes(kSecRandomDefault, nonceSize, nonce);
    return [NSString encodeBase64WithData:[NSData dataWithBytes:nonce length:nonceSize]];
}

- (NSString *)acceptKeyFromNonce:(NSString *)nonce {
    return [NSString encodeBase64WithData:[self SHA1DigestOfString:[nonce stringByAppendingString:WSAcceptGUID]]];    
}


#pragma mark - Data stream


- (void)initiateConnection {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)serverURL.host, 80, &readStream, &writeStream);
    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;
    inputStream.delegate = self;
    outputStream.delegate = self;
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];    
}

- (void)closeStream:(NSStream *)stream {
    [stream close];
    [stream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
}

- (void)readFromStream {
    if(!dataReceived) {
        dataReceived = [[NSMutableData alloc] init];
    }
    
    uint8_t buffer[bufferSize];
    NSInteger length = 0;
    
    length = [inputStream read:buffer maxLength:bufferSize];
    
    if (length > 0) {
        [dataReceived appendBytes:(const void *)buffer length:length];
        bytesRead += length;
    }
    else {
        NSLog(@"Read error!");
    }

    NSLog(@"bytesRead: %d", bytesRead);
    NSLog(@"Data received: %@", [[NSString alloc] initWithData:dataReceived encoding:NSUTF8StringEncoding]);
}

- (void)writeToStream {
    
    hasSpaceAvailable = YES;
    
    if (!dataToSend) {
        return;
    }
    
    uint8_t *dataBytes = (uint8_t *)[dataToSend mutableBytes];
    dataBytes += bytesSent;
    unsigned int length = (dataToSend.length - bytesSent) % bufferSize;
    uint8_t buffer[length];
    (void)memcpy(buffer, dataBytes, length);
    length = [outputStream write:buffer maxLength:length];
    
    if (length > 0) {
        bytesSent += length;
        
        if (bytesSent >= dataToSend.length) {
            dataToSend = nil;
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
            [self closeStream:aStream];
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

    NSLog(@"%@", handshake);
    NSLog(@"%@", [self acceptKeyFromNonce:nonce]);
}


#pragma mark - Public interface


- (void)open {
    [inputStream open];
    [outputStream open];
    [self sendOpeningHandshake];
}

- (void)close {
    [self closeStream:inputStream];
    [self closeStream:outputStream];
}

- (void)sendData:(NSData *)data {
    dataToSend = [NSMutableData dataWithData:data];
}

- (void)sendText:(NSString *)text {
    [self sendData:[text dataUsingEncoding:NSUTF8StringEncoding]];
}


#pragma mark - Object lifecycle


- (id)initWithUrl:(NSURL *)url {
    self = [super init];
    if (self) {
        [self analyzeURL:url];
        serverURL = url;
        [self initiateConnection];
    }
    return self;
}

@end
