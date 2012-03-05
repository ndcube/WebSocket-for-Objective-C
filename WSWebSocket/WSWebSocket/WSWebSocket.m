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
static NSString *const WSSecWebSocketVersion = @"Sec-WebSocket-Version";

static NSString *const WSHTTPCode101 = @"101";


typedef enum {
    WSWebSocketStateNone = 0,
    WSWebSocketStateConnecting = 1,
    WSWebSocketStateOpen = 2,
    WSWebSocketStateClosing = 3,
    WSWebSocketStateClosed = 4
}WSWebSocketStateType;

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
    NSData *dataToSend;
    NSInteger bytesSent;
    
    BOOL hasSpaceAvailable;
    
    NSMutableArray *messagesToSend;
    NSMutableArray *framesToSend;

    NSMutableData *messageConstructed;
    NSMutableData *messageProcessed;
    NSInteger bytesConstructed;
    NSInteger bytesProcessed;

    WSWebSocketStateType state;
    NSString *acceptKey;
    
    WSWebSocketOpcodeType messageProcessedType;
    WSWebSocketOpcodeType messageConstructedType;

    uint8_t mask[WSMaskSize];
    
    NSThread *wsThread;

    void (^textCallback)(NSString *text);
    void (^dataCallback)(NSData *data);
}


@synthesize fragmentSize;


#pragma mark - Object lifecycle


- (id)initWithUrl:(NSURL *)url textCallback:(void (^)(NSString *text))aTextCallback dataCallback:(void (^)(NSData *data))aDataCallback {
    self = [super init];
    if (self) {
        [self analyzeURL:url];
        messagesToSend = [[NSMutableArray alloc] init];
        framesToSend = [[NSMutableArray alloc] init];
        serverURL = url;
        fragmentSize = NSUIntegerMax;
        textCallback = aTextCallback;
        dataCallback = aDataCallback;
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
    SecRandomCopyBytes(kSecRandomDefault, WSMaskSize, mask);
}


#pragma mark - Data stream


- (void)initiateConnection {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    NSUInteger port = (serverURL.port) ? serverURL.port.integerValue : ([serverURL.scheme.lowercaseString isEqualToString:WSScheme.lowercaseString]) ? WSPort : WSPortSecure;
    
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)serverURL.host, port, &readStream, &writeStream);

    inputStream = (__bridge_transfer NSInputStream *)readStream;
    outputStream = (__bridge_transfer NSOutputStream *)writeStream;

    if ([serverURL.scheme isEqualToString:WSSchemeSecure]) {
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

- (void)close {
    [self closeConnection];
    state = WSWebSocketStateClosed;
    NSLog(@"WebSocket State Closed");
}


#pragma mark - Receive data


- (void)constructMessage {

    if (!dataReceived.length) {
        return;
    }
    
    BOOL isNewMessage = NO;
    
    if (!messageConstructed) {
        messageConstructed = [[NSMutableData alloc] init];
        isNewMessage = YES;
    }

    NSLog(@"Constructing message");
    
    uint8_t *dataBytes = (uint8_t *)[dataReceived bytes];
    dataBytes += bytesConstructed;

    NSUInteger frameSize = 2;
    uint64_t payloadLength = 0;
    
    // Mask bit must be clear
    if (dataBytes[1] & 0b10000000) {
        [self close];
        return;
    }
    
    // Determine message type
    if (isNewMessage) {
        messageConstructedType = dataBytes[0] & 0b01111111;
    }
    
    // Determine payload length
    if (dataBytes[1] < 126) {
        payloadLength = dataBytes[1];
    }
    else if (dataBytes[1] == 126) {
        frameSize += 2;
        uint16_t *payloadLength16 = (uint16_t *)(dataBytes + 2);
        payloadLength = CFSwapInt16BigToHost(*payloadLength16);
    }
    else {
        frameSize += 8;
        uint64_t *payloadLength64 = (uint64_t *)(dataBytes + 2);
        payloadLength = CFSwapInt64BigToHost(*payloadLength64);
    }
    
    uint8_t *payloadData = (uint8_t *)(dataBytes + frameSize);
    
    // Control frames
    if (dataBytes[0] & 0b00001000) {

        // Close frame
        if (dataBytes[0] & 0x8) {
            uint16_t *code16 = (uint16_t *)payloadData;
            uint16_t statusCode = CFSwapInt16BigToHost(*code16);
            payloadData += 2;
            NSString *controlMessage = [[NSString alloc] initWithBytes:payloadData length:payloadLength - 2 encoding:NSUTF8StringEncoding];
            [self sendCloseControlFrameWithStatusCode:statusCode message:controlMessage];
        }
    }
    // Data frames
    else {

        // Get payload data
        [messageConstructed appendBytes:payloadData length:payloadLength];
        
        // In case it was the final fragment
        if (dataBytes[0] & 0b10000000) {
            
            if (messageConstructedType == WSWebSocketOpcodeText && textCallback) {
                textCallback([[NSString alloc] initWithData:messageConstructed encoding:NSUTF8StringEncoding]);
            }
            else if (dataCallback) {
                dataCallback([NSData dataWithData:messageConstructed]);
            }
            
            messageConstructed = nil;
        }
    }

    bytesConstructed += (payloadLength + frameSize);
}

- (void)readFromStream {
    
    if(!dataReceived) {
        dataReceived = [[NSMutableData alloc] init];
    }
    
    NSUInteger bufferSize = fragmentSize;
    
    if (fragmentSize == NSUIntegerMax) {
        bufferSize = 4096;
    }
    
    uint8_t buffer[bufferSize];
    NSUInteger length = bufferSize;

    length = [inputStream read:buffer maxLength:bufferSize];
    
    if (length > 0) {
        [dataReceived appendBytes:(const void *)buffer length:length];
        NSLog(@"bytesRead: %d", length);
    }
    else {
        NSLog(@"Read error!");
    }
    
    if (state == WSWebSocketStateOpen) {
        [self constructMessage];
    }
    else if (state == WSWebSocketStateConnecting) {
        
        uint8_t *dataBytes = (uint8_t *)[dataReceived bytes];
        
        // Find end of the header
        for (int i = 0; i < dataReceived.length - 3; i++) {
            if (dataBytes[i] == 0x0d && dataBytes[i + 1] == 0x0a && dataBytes[i + 2] == 0x0d && dataBytes[i + 3] == 0x0a) {
                [self didReceiveResponseForOpeningHandshake];
                
                if (dataReceived.length == i + 4) {
                    dataReceived = nil;
                }
                else {
                    dataBytes += (i + 3);
                    dataReceived = [[NSMutableData alloc] initWithBytes:dataBytes length:dataReceived.length - (i + 3)];
                }
                
                break;
            }
        }
    }
    
    if (bytesConstructed == dataReceived.length) {
        dataReceived = nil;
        bytesConstructed = 0;
    }
}


#pragma mark - Send data


// Sends a frame of the given data
// Returns the length of the payload data
- (uint64_t)sendFrameWithType:(WSWebSocketOpcodeType)type data:(NSData *)data {

    uint8_t maskBitAndPayloadLength;
    
    // default frame size: sizeof(opcode) + sizeof(maskBitAndPayloadLength) + sizeof(mask)
    NSUInteger frameSize = 6;
    
    uint64_t totalLength = MIN((data.length + frameSize), fragmentSize);
    
    if (totalLength < 126) {
        maskBitAndPayloadLength = totalLength - frameSize;
    }
    else {
        totalLength = MIN(totalLength + 2, fragmentSize);
        
        if (totalLength < 65536) {
            maskBitAndPayloadLength = 126;
            frameSize += 2;
        }   
        else {
            totalLength = MIN(totalLength + 6, fragmentSize);
            maskBitAndPayloadLength = 127;
            frameSize += 8;
        }
    }
    
    uint64_t payloadLength = totalLength - frameSize;
    
    // Set the opcode
    uint8_t opcode = type;
        
    // Set fin bit
    if (payloadLength == data.length) {
        opcode |= 0b10000000;
    }
    
    uint8_t buffer[totalLength];
    
    // Store the opcode
    buffer[0] = opcode;
    
    // Set the mask bit
    maskBitAndPayloadLength |= 0b10000000;
    
    // Store mask bit and payload length
    buffer[1] = maskBitAndPayloadLength;
    
    if (payloadLength > 65535) {
        uint64_t *payloadLength64 = (uint64_t *)(buffer + 2);
        *payloadLength64 = CFSwapInt64HostToBig(payloadLength);
        *payloadLength64 = payloadLength;
    }
    else if (payloadLength > 125) {
        uint16_t *payloadLength16 = (uint16_t *)(buffer + 2);
        *payloadLength16 = CFSwapInt16HostToBig(payloadLength);
    }
    
    [self generateNewMask];
    
    // Store mask key
    uint8_t *mask8 = (uint8_t *)(buffer + frameSize - sizeof(mask));
    (void)memcpy(mask8, mask, sizeof(mask));
    
    // Store the payload data
    uint8_t *payloadData = (uint8_t *)(buffer + frameSize);
    (void)memcpy(payloadData, data.bytes, payloadLength);
    
    // Mask the payload data
    for (int i = 0; i < payloadLength; i++) {
        payloadData[i] ^= mask[i % 4];
    }

    NSData *frame = [NSData dataWithBytes:buffer length:totalLength];
    
    // Control frames
    if (buffer[0] & 0b00001000) {
        [framesToSend insertObject:frame atIndex:0];
    }
    else {
        [framesToSend addObject:frame];
    }

    return payloadLength;
}

- (void)processMessage {
    
    // If no message to process then return
    if (!messageProcessed) {
        return;
    }

    NSLog(@"Processing message");

    uint8_t *dataBytes = (uint8_t *)[messageProcessed bytes];
    dataBytes += bytesProcessed;

    uint8_t opcode = messageProcessedType;

    if (bytesProcessed) {
        opcode = WSWebSocketOpcodeContinuation;
    }

    NSData *data =[NSData dataWithBytesNoCopy:dataBytes length:messageProcessed.length - bytesProcessed freeWhenDone:NO];

    uint64_t payloadLength = [self sendFrameWithType:opcode data:data];
    bytesProcessed += payloadLength;
    
    // If all has been sent
    if (messageProcessed.length == bytesProcessed) {
        messageProcessed = nil;
        bytesProcessed = 0;
    }
}

- (void)writeToStream {
    
    if (!dataToSend) {
        return;
    }

    uint8_t *dataBytes = (uint8_t *)[dataToSend bytes];
    dataBytes += bytesSent;
    uint64_t length = dataToSend.length - bytesSent;
    uint8_t buffer[length];
    (void)memcpy(buffer, dataBytes, length);

    hasSpaceAvailable = NO;
    length = [outputStream write:buffer maxLength:length];

    if (length > 0) {
        bytesSent += length;
        
        if (bytesSent == dataToSend.length) {
            bytesSent = 0;
            dataToSend = nil;
        }
    }
    else {
        NSLog(@"Write error!");
    }
}

- (void)scheduleNextMessage {
    if (!messageProcessed && messagesToSend.count) {
        id objectToSend = [messagesToSend objectAtIndex:0];
        [messagesToSend removeObjectAtIndex:0];
        
        if ([objectToSend isKindOfClass:[NSString class]]) {
            messageProcessed = [NSMutableData dataWithData:[objectToSend dataUsingEncoding:NSUTF8StringEncoding]];
            messageProcessedType = WSWebSocketOpcodeText;
        }
        else {
            messageProcessed = [NSMutableData dataWithData:objectToSend];
            messageProcessedType = WSWebSocketOpcodeBinary;
        }
    }
}

- (void)scheduleNextFrame {
    if (!dataToSend && framesToSend.count) {
        dataToSend = [framesToSend objectAtIndex:0];
        [framesToSend removeObjectAtIndex:0];
    }
}

- (void)sendData {

    if (!hasSpaceAvailable) {
        return;
    }

    if (state == WSWebSocketStateOpen) {

        [self scheduleNextMessage];
        [self processMessage];
        [self scheduleNextFrame];
    }
    
    [self writeToStream];
}

#pragma mark - Control frames


- (void)sendCloseControlFrameWithStatusCode:(uint16_t)code message:(NSString *)message {
    
    state = WSWebSocketStateClosing;
    
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t length = (code) ? 2 + messageData.length : 0;
    
    // Create the data from the status code and the message
    if (length) {
        uint8_t buffer[length];
        uint8_t *payloadData = (uint8_t *)buffer;
        uint16_t *code16 = (uint16_t *)payloadData;
        *code16 = CFSwapInt16HostToBig(code);
        
        if (messageData.length) {
            payloadData += 2;
            (void)memcpy(payloadData, messageData.bytes, messageData.length);
        }
        [self sendFrameWithType:WSWebSocketOpcodeClose data:[NSData dataWithBytes:buffer length:length]];
    }
    
    NSLog(@"Closing frame status code: %d - Message: %@", code, message);
}


#pragma mark - NSStreamDelegate


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
            
            hasSpaceAvailable = YES;
            [self sendData];
            
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
    NSString *pathQuery = (serverURL.query) ? [NSString stringWithFormat:@"%@?%@", serverURL.path, serverURL.query] : serverURL.path.length ? serverURL.path : @"/";
    NSString *hostPort = (serverURL.port) ? [NSString stringWithFormat:@"%@:%@", serverURL.host, serverURL.port] : serverURL.host;
    
    NSString *handshake = [NSString stringWithFormat:
                           @"%@ %@ %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n%@: %@\r\n\r\n",
                           WSGet, pathQuery, WSHTTP11,
                           WSHost, hostPort,
                           WSUpgrade, WSUpgradeValue,
                           WSConnection, WSConnectionValue,
                           WSSecWebSocketVersion, WSVersion,
                           WSSecWebSocketKey, nonce];
    
    dataToSend = [NSMutableData dataWithData:[handshake dataUsingEncoding:NSUTF8StringEncoding]];
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

- (void)didReceiveResponseForOpeningHandshake {

    if ([self isValidHandshake:[[NSString alloc] initWithData:dataReceived encoding:NSUTF8StringEncoding]]) {
        state = WSWebSocketStateOpen;
        NSLog(@"WebSocket State Open");

        [self sendData];
    }
    else {
        [self close];
    }
}


#pragma mark - Thread


- (void)webSocketThreadLoop {

    @autoreleasepool {
        while (state != WSWebSocketStateClosed) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, NO);
            [NSThread sleepForTimeInterval:0.1];
        }
    }
}


#pragma mark - Threaded methods


- (void)threadedOpen {
    [self initiateConnection];
    [self sendOpeningHandshake];
}

- (void)threadedSendData:(NSData *)data {
    [messagesToSend addObject:data];
    
    [self sendData];
}

- (void)threadedSendText:(NSString *)text {
    [messagesToSend addObject:text];
    
    [self sendData];
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

- (void)sendData:(NSData *)data {
    [self performSelector:@selector(threadedSendData:) onThread:wsThread withObject:data waitUntilDone:NO];
}

- (void)sendText:(NSString *)text {
    [self performSelector:@selector(threadedSendText:) onThread:wsThread withObject:text waitUntilDone:NO];
}


@end
