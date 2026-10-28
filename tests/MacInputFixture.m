// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Manual synthetic fixture. No WeChat data, network or production policy.
#import <Cocoa/Cocoa.h>
@interface Messages:NSStackView @end
@implementation Messages
-(BOOL)isAccessibilityElement {return YES;}
-(NSString*)accessibilityRole {return NSAccessibilityListRole;}
-(NSArray*)accessibilityChildren {return self.arrangedSubviews;}
@end
@interface Delegate:NSObject<NSApplicationDelegate>
@property NSWindow *window;
@property NSTextField *input;
@property NSStackView *messages;
@end
@implementation Delegate
-(void)applicationDidFinishLaunching:(NSNotification*)notice {
 self.window=[[NSWindow alloc] initWithContentRect:NSMakeRect(200,180,640,480) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable backing:NSBackingStoreBuffered defer:NO];
 self.window.title=@"AXR synthetic input fixture";self.window.sharingType=NSWindowSharingReadOnly;
 NSArray *texts=@[@"fixture-account",@"fixture-chat",@"fixture-title"];
 NSArray *ids=@[@"account",@"identity",@"header"];
 for(NSInteger i=0;i<3;i++) {NSTextField *label=[NSTextField labelWithString:texts[i]];label.frame=NSMakeRect(20,420-i*40,550,30);label.font=[NSFont systemFontOfSize:24];label.accessibilityIdentifier=ids[i];[self.window.contentView addSubview:label];}
 self.messages=[[Messages alloc] initWithFrame:NSMakeRect(20,140,550,160)];self.messages.orientation=NSUserInterfaceLayoutOrientationVertical;self.messages.accessibilityIdentifier=@"messages";[self.window.contentView addSubview:self.messages];
 self.input=[[NSTextField alloc] initWithFrame:NSMakeRect(20,60,550,35)];self.input.accessibilityIdentifier=@"input";self.input.target=self;self.input.action=@selector(send:);[self.window.contentView addSubview:self.input];
 [self.window makeKeyAndOrderFront:nil];[self.window makeFirstResponder:self.input];[NSApp activateIgnoringOtherApps:YES];
}
-(void)send:(id)sender {if(self.input.stringValue.length){NSTextField *label=[NSTextField labelWithString:self.input.stringValue];label.accessibilityIdentifier=@"bubble";[self.messages addArrangedSubview:label];self.input.stringValue=@"";}}
@end
int main(){@autoreleasepool{NSApplication *app=[NSApplication sharedApplication];[app setActivationPolicy:NSApplicationActivationPolicyRegular];Delegate *d=[Delegate new];app.delegate=d;[app run];}}
