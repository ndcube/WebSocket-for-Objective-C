//
//  WSWebSocket.m
//  WSWebSocket
//
//  Created by Andras Koczka on 2/7/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "WSWebSocket.h"


static const NSInteger bufferSize = 1024;


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
            NSLog(@"Opened");
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
            NSLog(@"Closed");
            [self closeStream:aStream];
            break;
        default:
            NSLog(@"Unknown event");
            break;
    }
}


#pragma mark - Public interface


- (void)open {
    [inputStream open];
    [outputStream open];
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
