#import "BipKeyDerivationPlugin.h"
#import <bip_key_derivation/bip_key_derivation-Swift.h>

@implementation BipKeyDerivationPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftBipKeyDerivationPlugin registerWithRegistrar:registrar];
}
@end
