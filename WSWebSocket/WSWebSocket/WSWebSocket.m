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
    NSMutableArray *messageFramesToSend;
    NSMutableArray *controlFramesToSend;

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
        messageFramesToSend = [[NSMutableArray alloc] init];
        controlFramesToSend = [[NSMutableArray alloc] init];
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
    state = WSWebSocketStateClosed;
    NSLog(@"WebSocket State Closed");
}


#pragma mark - Receive data

- (BOOL)constructMessage {

    if (!dataReceived.length) {
        return NO;
    }
    
    if (!messageConstructed) {
        messageConstructed = [[NSMutableData alloc] init];
    }
    
    uint8_t *dataBytes = (uint8_t *)[dataReceived bytes];
    dataBytes += bytesConstructed;

    NSUInteger frameSize = 2;
    uint64_t payloadLength = 0;
    
    // Mask bit must be clear
    if (dataBytes[1] & 0b10000000) {
        [self sendCloseControlFrameWithStatusCode:1002 message:nil];
        return NO;
    }

    uint8_t opcode = dataBytes[0] & 0b01111111; 

    // Opcode should not be a reserved code
    if (opcode != WSWebSocketOpcodeContinuation && opcode != WSWebSocketOpcodeText && opcode != WSWebSocketOpcodeBinary && opcode != WSWebSocketOpcodeClose && opcode != WSWebSocketOpcodePing && opcode != WSWebSocketOpcodePong ) {
        [self sendCloseControlFrameWithStatusCode:1002 message:nil];
        return NO;
    }
    
    // Determine message type
    if (opcode == WSWebSocketOpcodeText || opcode == WSWebSocketOpcodeBinary) {
        messageConstructedType = opcode;
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
    
    // Frame is not received fully
    if (payloadLength + frameSize > dataReceived.length - bytesConstructed) {
//        NSLog(@"Frame is not received fully");
        return NO;
    }
    
    uint8_t *payloadData = (uint8_t *)(dataBytes + frameSize);
    
    // Control frames
    if (opcode & 0b00001000) {
        
        // Maximum payload length is 125
        if (payloadLength > 125) {
            [self sendCloseControlFrameWithStatusCode:1002 message:nil];
            return NO;
        }

        // Fin bit must be set
        if (~dataBytes[0] & 0b10000000) {
            [self sendCloseControlFrameWithStatusCode:1002 message:nil];
            return NO;
        }

        // Close frame
        if (opcode == WSWebSocketOpcodeClose) {
            uint16_t statusCode;
            NSString *controlMessage;
            
            if (payloadLength) {
                uint16_t *code16 = (uint16_t *)payloadData;
                statusCode = CFSwapInt16BigToHost(*code16);
                payloadData += 2;
                controlMessage = [[NSString alloc] initWithBytes:payloadData length:payloadLength - 2 encoding:NSUTF8StringEncoding];
            }
            
            [self sendCloseControlFrameWithStatusCode:statusCode message:controlMessage];
        }
        // Ping frame
        if (opcode == WSWebSocketOpcodePing) {
            NSString *controlMessage = [[NSString alloc] initWithBytes:payloadData length:payloadLength encoding:NSUTF8StringEncoding];
            if (controlMessage) {
                NSLog(@"Ping: %@", controlMessage);
            }
            [self sendFrameWithType:WSWebSocketOpcodePong data:[NSData dataWithBytes:payloadData length:payloadLength]];
            [self sendData];
        }
        // Pong frame
        if (opcode == WSWebSocketOpcodePong) {
            NSString *controlMessage = [[NSString alloc] initWithBytes:payloadData length:payloadLength encoding:NSUTF8StringEncoding];
            NSLog(@"Pong: %@", controlMessage);
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
    
    return YES;
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
    NSInteger length = bufferSize;

    length = [inputStream read:buffer maxLength:bufferSize];

    if (length > 0) {
        [dataReceived appendBytes:(const void *)buffer length:length];
    }
    else {
        NSLog(@"Read error!");
        return;
    }

    if (state == WSWebSocketStateConnecting) {
        
        uint8_t *dataBytes = (uint8_t *)[dataReceived bytes];
        
        // Find end of the header
        for (int i = 0; i < dataReceived.length - 3; i++) {
            if (dataBytes[i] == 0x0d && dataBytes[i + 1] == 0x0a && dataBytes[i + 2] == 0x0d && dataBytes[i + 3] == 0x0a) {
                NSData *handshake = [NSData dataWithBytesNoCopy:dataReceived.mutableBytes length:i + 4 freeWhenDone:NO];
                
                [self didReceiveOpeningHandshakeWithData:handshake];
                
                if (dataReceived.length == i + 4) {
                    dataReceived = nil;
                }
                else {
                    dataBytes += (i + 4);
                    dataReceived = [[NSMutableData alloc] initWithBytes:dataBytes length:dataReceived.length - (i + 4)];
                }
                break;
            }
        }
    }    

    if (state == WSWebSocketStateOpen || state == WSWebSocketStateClosing) {
        
        while (bytesConstructed != dataReceived.length && [self constructMessage]) {
        }
        
        if (bytesConstructed == dataReceived.length) {
            dataReceived = nil;
            bytesConstructed = 0;
        }
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
    
    if (totalLength - frameSize < 126) {
        maskBitAndPayloadLength = totalLength - frameSize;
    }
    else {
        totalLength = MIN(totalLength + 2, fragmentSize);
        frameSize += 2;
        
        if (totalLength - frameSize < 65536) {
            maskBitAndPayloadLength = 126;
        }   
        else {
            totalLength = MIN(totalLength + 6, fragmentSize);
            maskBitAndPayloadLength = 127;
            frameSize += 6;
        }
    }
    
    uint64_t payloadLength = totalLength - frameSize;
    
    // Set the opcode
    uint8_t opcode = type;
        
    // Set fin bit
    if (payloadLength == data.length) {
        opcode |= 0b10000000;
    }
    
    NSMutableData *payloadData = [[NSMutableData alloc] initWithLength:totalLength];
    
    uint8_t *payloadDataBytes = (uint8_t *)(payloadData.mutableBytes);
    
    // Store the opcode
    payloadDataBytes[0] = opcode;
    
    // Set the mask bit
    maskBitAndPayloadLength |= 0b10000000;
    
    // Store mask bit and payload length
    payloadDataBytes[1] = maskBitAndPayloadLength;
    
    if (payloadLength > 65535) {
        uint64_t *payloadLength64 = (uint64_t *)(payloadDataBytes + 2);
        *payloadLength64 = CFSwapInt64HostToBig(payloadLength);
    }
    else if (payloadLength > 125) {
        uint16_t *payloadLength16 = (uint16_t *)(payloadDataBytes + 2);
        *payloadLength16 = CFSwapInt16HostToBig(payloadLength);
    }
    
    [self generateNewMask];
    
    // Store mask key
    uint8_t *mask8 = (uint8_t *)(payloadDataBytes + frameSize - sizeof(mask));
    (void)memcpy(mask8, mask, sizeof(mask));
    
    // Store the payload data
    payloadDataBytes += frameSize;
    (void)memcpy(payloadDataBytes, data.bytes, payloadLength);
    
    // Mask the payload data
    for (int i = 0; i < payloadLength; i++) {
        payloadDataBytes[i] ^= mask[i % 4];
    }

    if (opcode & 0b00001000) {
        [controlFramesToSend addObject:payloadData];
    }
    else {
        [messageFramesToSend addObject:payloadData];
    }

    return payloadLength;
}

- (void)processMessage {
    // If no message to process then return
    if (!messageProcessed) {
        return;
    }

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

    hasSpaceAvailable = NO;
    length = [outputStream write:dataBytes maxLength:length];
    
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
    if (!dataToSend && controlFramesToSend.count) {
        dataToSend = [controlFramesToSend objectAtIndex:0];
        [controlFramesToSend removeObjectAtIndex:0];
    }
    
    if (!dataToSend && messageFramesToSend.count) {
        dataToSend = [messageFramesToSend objectAtIndex:0];
        [messageFramesToSend removeObjectAtIndex:0];
    }
}

- (void)sendData {
    if (!hasSpaceAvailable) {
        return;
    }

    if (state == WSWebSocketStateOpen || state == WSWebSocketStateClosing) {

        if (state == WSWebSocketStateOpen) {
            [self scheduleNextMessage];
            [self processMessage];
        }
        [self scheduleNextFrame];
    }
    
    [self writeToStream];
}


#pragma mark - Control frames


- (void)sendCloseControlFrameWithStatusCode:(uint16_t)code message:(NSString *)message {
    
    if (state != WSWebSocketStateOpen) {
        return;
    }
    
    state = WSWebSocketStateClosing;
    
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t length = (code) ? 2 + messageData.length : 0;

    NSData *frameData;
    
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
        
        frameData = [NSData dataWithBytes:buffer length:length];
    }
    
    [self sendFrameWithType:WSWebSocketOpcodeClose data:frameData];
    
    NSLog(@"Closing frame status code: %d - Message: %@", code, message);

    [self sendData];
}

- (void)sendPingControlFrameWithText:(NSString *)text {
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    [self sendFrameWithType:WSWebSocketOpcodePing data:data];
}

- (void)sendPongControlFrameWithText:(NSString *)text {
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    [self sendFrameWithType:WSWebSocketOpcodePong data:data];
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
            else {
                NSLog(@"HEY - output has bytes available?");
            }
            break;
        case NSStreamEventHasSpaceAvailable:            
            if (aStream == outputStream) {
                hasSpaceAvailable = YES;
                [self sendData];
            }
            else {
                NSLog(@"HEY - input has space available?");
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

- (void)didReceiveOpeningHandshakeWithData:(NSData *)handshakeData {

    if ([self isValidHandshake:[[NSString alloc] initWithData:handshakeData encoding:NSUTF8StringEncoding]]) {
        state = WSWebSocketStateOpen;
        NSLog(@"WebSocket State Open %@", serverURL.absoluteString);

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
    if (!data) {
        return;
    }
    
    [self performSelector:@selector(threadedSendData:) onThread:wsThread withObject:data waitUntilDone:NO];
}

- (void)sendText:(NSString *)text {
    if (!text) {
        return;
    }
    
    [self performSelector:@selector(threadedSendText:) onThread:wsThread withObject:text waitUntilDone:NO];
}

- (void)sendPingWithText:(NSString *)text {
    [self performSelector:@selector(sendPingControlFrameWithText:) onThread:wsThread withObject:text waitUntilDone:NO];
}

@end
