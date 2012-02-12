//
//  WSWebSocket.h
//  WSWebSocket
//
//  Created by Andras Koczka on 2/7/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WSWebSocket : NSObject <NSStreamDelegate>

- (id)initWithUrl:(NSURL *)url;
- (void)open;
- (void)close;
- (void)sendData:(NSData *)data;
- (void)sendText:(NSString *)text;

@end
