//
//  WSWebSocket.h
//  WSWebSocket
//
//  Created by Andras Koczka on 2/7/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 The class is responsible for establishing a websocket connection to the specified URL, sending/receiving messages and closing the connection.
 */
@interface WSWebSocket : NSObject <NSStreamDelegate>

/**
 Specifies the maximum fragment size to use. Minimum fragment size is 131 bytes.
 */
@property (assign, nonatomic) NSUInteger fragmentSize;

/**
 The host url.
 */
@property (strong, nonatomic, readonly) NSURL *hostURL;

/**
 Designated initializer.
 @param url The url of the server to connect
 */
- (id)initWithURL:(NSURL *)url;

/**
 Opens the connection.
 */
- (void)open;

/**
 Closes the connection.
 */
- (void)close;

/**
 Sends the given data.
 @param data The data to be sent
 */
- (void)sendData:(NSData *)data;

/**
 Sends the given text. Text should be UTF8 encoded.
 @param text The text to be sent.
 */
- (void)sendText:(NSString *)text;

/**
 Sends a ping message with the specified data.
 @param data Additional data to be sent as part of the ping message. Maximum data size is 125 bytes.
 */
- (void)sendPingWithData:(NSData *)data;

/**
 Sets a data callback block that will be called whenever a message with data is received.
 @param dataCallback The callback block
 */
- (void)setDataCallback:(void (^)(NSData *data))dataCallback;

/**
 Sets a text callback block that will be called whenever a text message is received.
 @param textCallback The callback block
 */
- (void)setTextCallback:(void (^)(NSString *text))textCallback;

/**
 Sets a pong callback block that will be called whenever a pong is received.
 @param pongCallback The callback block
 */
- (void)setPongCallback:(void (^)(void))pongCallback;

/**
 Sets a callback block that will be called after the connection is closed.
 @param closeCallback The callback block
 */
- (void)setCloseCallback:(void (^)(NSUInteger statusCode, NSString *message))closeCallback;

@end
