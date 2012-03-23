//
//  WSFrame.h
//  WSWebSocket
//
//  Created by Andras Koczka on 3/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    WSWebSocketOpcodeContinuation = 0,
    WSWebSocketOpcodeText = 1,
    WSWebSocketOpcodeBinary = 2,
    WSWebSocketOpcodeClose = 8,
    WSWebSocketOpcodePing = 9,
    WSWebSocketOpcodePong = 10
}WSWebSocketOpcodeType;


/**
 WebSocket frame to be send to a server.
 */
@interface WSFrame : NSObject

/**
 The type of the frame.
 */
@property (assign, nonatomic, readonly) WSWebSocketOpcodeType opcode;

/**
 The frame data.
 */
@property (strong, nonatomic, readonly) NSMutableData *data;

/**
 The length of the payload.
 */
@property (assign, nonatomic, readonly) uint64_t payloadLength;

/**
 Yes if the frame is a control frame.
 */
@property (assign, nonatomic, readonly) BOOL isControlFrame;

/**
 Designated initializer. Creates a new frame with the given type and data.
 @param opcode The opcode of the message
 @param data The payload data to be processed
 @param maxSize The maximum size of the frame
 */
- (id)initWithOpcode:(WSWebSocketOpcodeType)opcode data:(NSData *)data maxSize:(NSUInteger)maxSize;

@end
