#import <Cocoa/Cocoa.h>
#include <stdlib.h>
static NSMutableArray *pending;
static NSMutableDictionary *leaves;
@interface BCElement : NSAccessibilityElement
@property(nonatomic,strong) NSString *key;
@property(nonatomic,strong) NSString *kind;
@property(nonatomic,strong) NSString *currentValue;
@property(nonatomic) BOOL available;
@property(nonatomic) BOOL focused;
@end
static void enqueue(NSString *key,NSString *value) {
  @synchronized([BCElement class]) {
    if (!pending) pending=[NSMutableArray new];
    [pending addObject:@{@"key":key,@"value":value?:@""}];
  }
}
@implementation BCElement
- (BOOL)isAccessibilityElement {return YES;}
- (BOOL)isAccessibilityFocused {return self.focused;}
- (NSString*)accessibilityRole {return [self.kind isEqual:@"field"]?NSAccessibilityTextFieldRole:([self.kind isEqual:@"button"]?NSAccessibilityButtonRole:NSAccessibilityStaticTextRole);}
- (id)accessibilityValue {return self.currentValue;}
- (BOOL)isAccessibilityEnabled {return self.available;}
- (BOOL)accessibilityPerformPress {if(!self.available)return NO;enqueue([self.kind isEqual:@"field"]?[@"focus:" stringByAppendingString:self.key]:self.key,@"");return YES;}
- (void)setAccessibilityValue:(id)value {if(self.available&&[self.kind isEqual:@"field"])enqueue(self.key,[value description]);}
- (BOOL)isAccessibilitySelectorAllowed:(SEL)selector {
 if(selector==@selector(setAccessibilityValue:))return self.available&&[self.kind isEqual:@"field"];
 if(selector==@selector(accessibilityPerformPress))return self.available&&([self.kind isEqual:@"button"]||[self.kind isEqual:@"field"]);
 return [super isAccessibilitySelectorAllowed:selector];
}
- (void)setAccessibilityFocused:(BOOL)focused {if(focused)enqueue([@"focus:" stringByAppendingString:self.key],@"");}
@end
void bc_ax_update(const char *json) {
 NSData *data=[[NSString stringWithUTF8String:json] dataUsingEncoding:NSUTF8StringEncoding];
 NSArray *items=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
 dispatch_async(dispatch_get_main_queue(), ^{
  NSWindow *window=NSApp.windows.firstObject;
  if(!window||!window.contentView)return;
  NSView *view=window.contentView;
  window.contentMinSize=NSMakeSize(320,400);
  if(!leaves)leaves=[NSMutableDictionary new];
  NSMutableArray *children=[NSMutableArray new];
  for(NSDictionary *item in items){
   NSString *key=item[@"id"];
   BCElement *element=leaves[key];
   if(!element){element=[BCElement new];element.key=key;leaves[key]=element;}
   element.kind=item[@"kind"];
   BOOL valueChanged=![element.currentValue isEqual:item[@"value"]];
   element.currentValue=item[@"value"];
   BOOL focusChanged=!element.focused&&[item[@"focused"] boolValue];
   element.focused=[item[@"focused"] boolValue];
   element.available=[item[@"enabled"] boolValue];
   element.accessibilityLabel=item[@"label"];element.accessibilityParent=view;
   NSArray *r=item[@"rect"];
   NSRect local=NSMakeRect([r[0] doubleValue],view.bounds.size.height-[r[1] doubleValue]-[r[3] doubleValue],[r[2] doubleValue],[r[3] doubleValue]);
   element.accessibilityFrame=[window convertRectToScreen:[view convertRect:local toView:nil]];
   [children addObject:element];
   if(valueChanged)NSAccessibilityPostNotification(element,NSAccessibilityValueChangedNotification);
   if(focusChanged)NSAccessibilityPostNotification(element,NSAccessibilityFocusedUIElementChangedNotification);
  }
  BOOL changed=![[view accessibilityChildren] isEqual:children];
  view.accessibilityElement=YES;view.accessibilityRole=NSAccessibilityGroupRole;
  view.accessibilityLabel=@"Elements wallet";view.accessibilityChildren=children;
  if(changed)NSAccessibilityPostNotification(view,NSAccessibilityLayoutChangedNotification);
 });
}
char *bc_ax_poll(void){
 @synchronized([BCElement class]){
  if(!pending.count)return strdup("[]");
  NSData *data=[NSJSONSerialization dataWithJSONObject:pending options:0 error:nil];
  [pending removeAllObjects];
  return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
 }
}
