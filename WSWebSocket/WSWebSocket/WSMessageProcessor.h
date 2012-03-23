//
//  WSMessageProcessor.h
//  WSWebSocket
//
//  Created by Andras Koczka on 3/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

@class WSFrame;
@class WSMessage;

/**
 This class is responsible for constructing/processing messages.
 */
@interface WSMessageProcessor : NSObject

/**
 Specifies the maximum fragment size to use.
 */
@property (assign, nonatomic) NSUInteger fragmentSize;

/**
 Number of bytes constructed.
 */
@property (assign, nonatomic) NSUInteger bytesConstructed;

/**
 Constructs a message from the received data.
 @param data The data to process
 */
- (WSMessage *)constructMessageFromData:(NSData *)data;

/**
 Queues a message to send.
 @param message The message to send
 */
- (void)queueMessage:(WSMessage *)message;

/**
 Schedules the next message.
 */
- (void)scheduleNextMessage;

/**
 Processes the current message;
 */
- (void)processMessage;

/**
 Queues a frame to send.
 @param frame The frame to send
 */
- (void)queueFrame:(WSFrame *)frame;

/**
 Returns the next frame to send.
 */
- (WSFrame *)nextFrame;

@end
