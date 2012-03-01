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


static const NSUInteger WSNonceSize = 16;
static const NSUInteger WSMaskSize = 4;
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
static NSString *const WSSecWebSocketProtocolClient = @"Sec-WebSocket-Protocol-Client";
static NSString *const WSSecWebSocketProtocolServer = @"Sec-WebSocket-Protocol-Server";
static NSString *const WSSecWebSocketVersion = @"Sec-WebSocket-Version";
static NSString *const WSSecWebSocketVersionClient = @"Sec-WebSocket-Version-Client";
static NSString *const WSSecWebSocketVersionServer = @"Sec-WebSocket-Version-Server";

static NSString *const WSHTTPCode101 = @"101";


typedef enum {
    WSWebSocketStateNone = 0,
    WSWebSocketStateConnecting = 1,
    WSWebSocketStateOpen = 2,
    WSWebSocketStateClosing = 3,
    WSWebSocketStateClosed = 4
}WSWebSocketStateType;

typedef enum {
    WSWebSocketMessageStateNone = 0,
    WSWebSocketMessageStateSending = 1
}WSWebSocketMessageStateType;

typedef enum {
    WSWebSocketOpcodeContinuation = 0,
    WSWebSocketOpcodeText = 1,
    WSWebSocketOpcodeBinary = 2,
    WSWebSocketOpcodeClose = 8,
    WSWebSocketOpcodePing = 9,
    WSWebSocketOpcodePong = 10
}WSWebSocketOpcodeType;


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
    
    WSWebSocketOpcodeType messageType;
    WSWebSocketMessageStateType messageState;
    
    uint64_t fragmentSize;
    uint8_t mask[WSMaskSize];
}


#pragma mark - Object lifecycle


- (id)initWithUrl:(NSURL *)url {
    self = [super init];
    if (self) {
        datasReceived = [[NSMutableArray alloc] init];
        datasToSend = [[NSMutableArray alloc] init];
        [self analyzeURL:url];
        serverURL = url;
        fragmentSize = 1024;
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
    uint8_t nonce[WSNonceSize];
    SecRandomCopyBytes(kSecRandomDefault, WSNonceSize, nonce);
    return [NSString encodeBase64WithData:[NSData dataWithBytes:nonce length:WSNonceSize]];
}

- (NSString *)acceptKeyFromNonce:(NSString *)nonce {
    return [NSString encodeBase64WithData:[self SHA1DigestOfString:[nonce stringByAppendingString:WSAcceptGUID]]];    
}

- (void)generateNewMask {
    uint8_t maskBytes[WSMaskSize];
    SecRandomCopyBytes(kSecRandomDefault, WSMaskSize, maskBytes);
}


#pragma mark - Data stream


- (void)initiateConnection {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    NSUInteger port = ([serverURL.scheme.lowercaseString isEqualToString:WSScheme.lowercaseString]) ? WSPort : WSPortSecure;
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)serverURL.host, port, &readStream, &writeStream);

    NSLog(@"%d", port);
    
    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;

    if (port == WSPortSecure) {
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
}

- (void)readFromStream {
    if(!dataReceived) {
        dataReceived = [[NSMutableData alloc] init];
    }
    
    uint8_t buffer[fragmentSize];
    NSInteger length = 0;
    
    length = [inputStream read:buffer maxLength:fragmentSize];

    if (state == WSWebSocketStateOpen) {

        NSUInteger frameSize = 2;
        uint64_t payloadLength = 0;

        if (length == 0) {
            NSLog(@"Read nothing");
            return;
        }
        
        if (length < 3 || buffer[1] > 128) {
            [self close];
            return;
        }
        
        if (buffer[1] < 126) {
            payloadLength = buffer[1];
        }
        else if (buffer[1] == 126) {
            frameSize += 2;
            uint16_t *payloadLength16 = (uint16_t *)(buffer + 2);
            payloadLength = *payloadLength16;
        }
        else {
            frameSize += 8;
            uint64_t *payloadLength64 = (uint64_t *)(buffer + 2);
            payloadLength = *payloadLength64;
        }
        
        uint8_t *payloadData = (uint8_t *)(buffer + frameSize);
        [dataReceived appendBytes:payloadData length:payloadLength];
        bytesRead += length;
    }

    if (state == WSWebSocketStateConnecting) {
        if (length > 0) {
            [dataReceived appendBytes:(const void *)buffer length:length];
            bytesRead += length;
            NSLog(@"bytesRead: %d", bytesRead);
        }
        else {
            NSLog(@"Read error!");
        }    
    }

    if (state == WSWebSocketStateOpen && buffer[0] > 127) {
        if (buffer[0] == 128 + 1) {
            [datasReceived addObject:[[NSString alloc] initWithData:dataReceived encoding:NSUTF8StringEncoding]];
        }
        else {
            [datasReceived addObject:dataReceived];    
        }

        [self didReceiveData];
    }
    
    if (state == WSWebSocketStateConnecting && bytesRead < fragmentSize) {
        [self didReceiveData];
    }
}

- (void)writeToStream {
    
    hasSpaceAvailable = YES;

    if (!dataToSend) {
        [self scheduleDataToSend];
    }

    if (!dataToSend) {
        return;
    }

    uint8_t *dataBytes = (uint8_t *)[dataToSend mutableBytes];
    dataBytes += bytesSent;
    
    uint8_t opcode = messageType;
    uint64_t length = (dataToSend.length - bytesSent) % fragmentSize;
    
    if (state == WSWebSocketStateOpen) {
        
        NSLog(@"Sending data");
        
        if (messageState == WSWebSocketMessageStateSending) {
            opcode = WSWebSocketOpcodeContinuation;
        }
        else {
            [self generateNewMask];
            messageState = WSWebSocketMessageStateSending;
        }

        uint8_t maskBitAndPayloadLength;
        uint64_t payloadLength;
        NSUInteger frameSize = sizeof(opcode) + sizeof(maskBitAndPayloadLength) + sizeof(mask);
        
        if (length < 126) {
            maskBitAndPayloadLength = 128 + 125;
        }
        else if (length < 65536) {
            maskBitAndPayloadLength = 128 + 126;
            frameSize += 2;
        }
        else {
            maskBitAndPayloadLength = 128 + 127;
            frameSize += 8;
        }
        
        length += frameSize;
        
        if (length <= fragmentSize) {
            opcode += 128;
        }
        else {
            length = fragmentSize;
        }

        payloadLength = length - frameSize;

        uint8_t buffer[length];
        buffer[0] = opcode;
        
        uint16_t *payloadLength16 = (uint16_t *)(buffer + 2);
        uint64_t *payloadLength64 = (uint64_t *)(buffer + 2);
        
        if (payloadLength < 126) {
            maskBitAndPayloadLength = 128 + payloadLength;
        }
        else if (payloadLength < 65536) {
            *payloadLength16 = payloadLength;
        }
        else {
            *payloadLength64 = payloadLength;
        }

        buffer[1] = maskBitAndPayloadLength;

        uint8_t *mask8 = (uint8_t *)(buffer + frameSize - sizeof(mask));
        mask8[0] = mask[0];
        mask8[1] = mask[1];
        mask8[2] = mask[2];
        mask8[3] = mask[3];
        
        uint8_t *payloadData = (uint8_t *)(buffer + frameSize);
        
        (void)memcpy(payloadData, dataBytes, payloadLength);

        for (int i = 0; i < payloadLength; i++) {
            payloadData[i] ^= mask[i % 4];
        }
        
        NSLog(@"%u, %u, %qu, %qu", buffer[0], buffer[1], length, payloadLength);
        
        length = [outputStream write:buffer maxLength:length];
        
        NSLog(@"%qu", length);
        
        if (opcode > 128) {
            [self didSendData];
        }
    }
    else {
        
        NSLog(@"Sending handshake");

        uint8_t buffer[length];
        (void)memcpy(buffer, dataBytes, length);
        length = [outputStream write:buffer maxLength:length];
    }
    
    if (state == WSWebSocketStateConnecting) {
        if (length > 0) {
            bytesSent += length;
            
            if (bytesSent >= dataToSend.length) {
                [self didSendData];
            }
        }
        else {
            NSLog(@"Write error!");
        }
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


#pragma mark - Data handling


- (void)scheduleDataToSend {
    if (state == WSWebSocketStateOpen && datasToSend.count) {
        id objectToSend = [datasToSend objectAtIndex:0];
        [datasToSend removeObjectAtIndex:0];
        
        if ([objectToSend isKindOfClass:[NSString class]]) {
            dataToSend = [NSMutableData dataWithData:[objectToSend dataUsingEncoding:NSUTF8StringEncoding]];
            messageType = WSWebSocketOpcodeText;
        }
        else {
            dataToSend = [NSMutableData dataWithData:objectToSend];
            messageType = WSWebSocketOpcodeBinary;
        }
    }   
}


#pragma mark - Events


- (void)didReceiveResponseForOpeningHandshake {

    if ([self isValidHandshake:[[NSString alloc] initWithData:dataReceived encoding:NSUTF8StringEncoding]]) {
        state = WSWebSocketStateOpen;
        NSLog(@"WebSocket State Open");

        if (hasSpaceAvailable) {
            [self writeToStream];
        }
    }
    else {
        [self close];
    }
}

- (void)didSendData {
    messageType = WSWebSocketMessageStateNone;
    dataToSend = nil;
    bytesSent = 0;
    [self scheduleDataToSend];

    if (hasSpaceAvailable) {
        [self writeToStream];
    }
}

- (void)didReceiveData {
    bytesRead = 0;

    if (state == WSWebSocketStateConnecting) {
        [self didReceiveResponseForOpeningHandshake];
    }
    
    dataReceived = nil;
    
    NSLog(@"%@", [datasReceived lastObject]);
}


#pragma mark - Public interface


- (void)open {
    state = WSWebSocketStateConnecting;
    [self initiateConnection];
    [self sendOpeningHandshake];
}

- (void)close {
    [self closeConnection];
    state = WSWebSocketStateClosed;
    NSLog(@"WebSocket State Closed");
}

- (void)sendData:(NSData *)data {
    [datasToSend addObject:data];
}

- (void)sendText:(NSString *)text {
    [datasToSend addObject:text];
}


@end
