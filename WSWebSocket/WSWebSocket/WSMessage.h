//
//  WSMessage.h
//  WSWebSocket
//
//  Created by Andras Koczka on 3/22/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WSFrame.h"

/**
 Message for communicating with a WebSocket server.
 */
@interface WSMessage : NSObject

/**
 The type of the message.
 */
@property (assign, nonatomic) WSWebSocketOpcodeType opcode;

/**
 The message data.
 */
@property (strong, nonatomic) NSData *data;

/**
 The message text.
 */
@property (strong, nonatomic) NSString *text;

/**
 The status code.
 */
@property (assign, nonatomic) NSInteger statusCode;


@end
