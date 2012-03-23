//
//  NSString+Base64.h
//  WSWebSocket
//
//  Created by Andras Koczka on 2/29/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Category for creating base64 encoded strings.
 */
@interface NSString (Base64)

/**
 Base64 encodes the given string.
 @param strData The string to encode.
 */
+ (NSString *)encodeBase64WithString:(NSString *)strData;

/**
 Base64 encodes the given data.
 @param objData The data to encode.
 */
+ (NSString *)encodeBase64WithData:(NSData *)objData;

@end
