//
//  WSWebSocket.h
//  WSWebSocket
//
//  Created by Andras Koczka on 2/7/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WSWebSocket : NSObject <NSStreamDelegate>

// Min fragment size is 131
@property (assign, nonatomic) NSUInteger fragmentSize;

- (id)initWithURL:(NSURL *)url;
- (void)open;
- (void)close;

- (void)sendData:(NSData *)data;
- (void)sendText:(NSString *)text;
- (void)sendPingWithData:(NSData *)data;

- (void)setDataCallback:(void (^)(NSData *data))dataCallback;
- (void)setTextCallback:(void (^)(NSString *text))textCallback;
- (void)setPongCallback:(void (^)(void))pongCallback;
- (void)setCloseCallback:(void (^)(NSUInteger statusCode, NSString *message))closeCallback;

@end
