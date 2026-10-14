// dmmb_offline_dump_mac.m -- macOS offline .dmmb extractor using the OFFICIAL
// local stack. The Windows backend is dmmb_offline_dump_win.cpp; the shared
// entry point is dmmb_offline.py. See docs/macos.md and docs/windows.md.
//
// Decrypts a .dmmb capsule with YOUR installed DMMbookviewer +
// CypherGuard.framework and YOUR machine's cached license
// (/Users/Shared/.Cypher License Information/...). No web download, no keys
// extracted, no crypto reimplemented: the content key is unwrapped inside
// CypherGuard from the device-bound service key, exactly as the viewer does.
//
// Requirement: the book must have a LOCAL license (open it once in
// DMMbookviewer while online). Fully offline afterwards.
//
// Pipeline (all app/flibrary entry points, reverse-engineered from
// DMMbookviewer 3.1.32.0 -- see docs/macos.md):
//   dlopen viewer + CypherGuard
//   allow-list register + security-context init + license-engine init
//     (+[__CPIR_t_0C8i9vQfEfuH2v initWTwqPul:...] with the app's config blob,
//      +[__CPIR_xuEB8tW4mM4ICMgq __CPIR_n3ghqzX5ZQuTmaE1],
//      -[CPSecurityLibraryManager __CPIR_8gnYLpUGPL8T1Iht],
//      -[CPSecurityLibraryManager __CPIR_6LurX5PjdM0OlSU5],
//      -[CPSecurityLibraryManager __CPIR_qKA6iTbAya3qEK4o],
//      context aroma=1 (as the startup success path records it))
//   +[CPCapsulizedFile capsulizedFileWithContentsOfFile:error:]
//   -[CPSecurityLibraryManager loadServiceToCapsulizedFile:error:]
//     (validates service, applies cached serviceKey)
//   -[CPSecurityLibraryManager lookupLocalLicenseWithCapsulizedFile:error:]
//   -[CPAuthentication applyLicense:error:]  (+ isValid)
//   -[capsule __CPIR_3gCXLasSyrMNtB58:]  (16-byte key material from descriptor)
//   -[capsule __CPIR_lvQQsXOCAF0pDlss]   (charge -> unlocked variant)
//   per entry: DRM loader + interpreter -> CPContentDecryptor
//     (mirrors -[__CPIR_9XWutw_U4gqVjnCz __CPIR_NKA6...], which the legacy
//     decryptorForSummary:/decryptors wrappers never reach for this flavor)
//   -> original bytes + manifest.json
//
// Rationale for hosting out-of-process: the Security Library only finishes
// init inside a process that runs the startup sequence; DYLD injection into
// the viewer is refused (hardened runtime, no dyld env entitlement), so this
// tool hosts the same calls in its own x86_64 process under Rosetta.
//
// Build (native clang targeting x86_64; the viewer binary is x86_64-only):
//   clang -arch x86_64 -framework Foundation -o dmmb_offline_dump_mac dmmb_offline_dump_mac.m
// Run:
//   arch -x86_64 ./dmmb_offline_dump_mac <file.dmmb> <outdir>
// Exit codes: 0 ok, 2 no local license, 3 decrypt failure, 4 usage/io error.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>

// Forward declarations -- no private headers needed.
@interface CPCapsulizedFile : NSObject
+ (id)capsulizedFileWithContentsOfFile:(NSString *)p error:(NSError **)e;
- (BOOL)applyLicense:(id)lic error:(NSError **)e;
- (NSArray *)packagingFilesSummary;
- (id)decryptorForSummary:(id)s;
@end
@interface CPSecurityLibraryManager : NSObject
+ (id)sharedManager;
- (id)lookupLocalLicenseWithCapsulizedFile:(id)f error:(NSError **)e;
- (BOOL)loadServiceToCapsulizedFile:(id)f error:(NSError **)e;
@end
@interface CPContentDecryptor : NSObject
- (NSData *)originalDataWithError:(NSError **)e;
- (NSData *)dataWithError:(NSError **)e;
- (unsigned long long)originalSize;
@end
@interface CPPackagingFileSummary : NSObject
- (NSString *)filename;
- (unsigned long long)filesize;
- (BOOL)isEncrypted;
@end

static const char *kViewer =
    "/Applications/DMMbookviewer.app/Contents/MacOS/DMMbookviewer";
static const char *kCG =
    "/Applications/DMMbookviewer.app/Contents/Frameworks/CypherGuard.framework/"
    "Versions/A/CypherGuard";
// Allow-list config blob baked into the viewer (sub_1000F71A0).
static NSString *kAccessCode(void) {
  return @"VwABAS0AuF8BDrZfOsvwQOx9M2pU2T40/hczV/4XVYgtGlYkR8/vz1aUiafuQuiVHFYSm6CGfWZILyfEhuYGf46b7J32KeiCEiP8mtkUTQRtMexwjbvO7XuC1Xr5XRnIATj4kQ2Vwd6SgD4Xu417ipmAy3l7fTE=";
}

static NSString *kindOf(NSData *d) {
  const uint8_t *b = d.bytes; NSUInteger n = d.length;
  if (n >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return @"jpeg";
  if (n >= 4 && b[0] == 'P' && b[1] == 'K') return @"zip";
  if (n >= 4 && !memcmp(b, "\x89PNG", 4)) return @"png";
  if (n >= 5 && !memcmp(b, "<?xml", 5)) return @"xml";
  return @"bin";
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc < 3) {
      fprintf(stderr, "usage: dmmb_offline_dump_mac <file.dmmb> <outdir>\n");
      return 4;
    }
    NSString *path = @(argv[1]);
    NSString *outdir = @(argv[2]);
    NSError *err = nil;

    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
      fprintf(stderr, "no such file: %s\n", argv[1]);
      return 4;
    }
    if (!dlopen(kViewer, RTLD_NOW | RTLD_GLOBAL)) {
      fprintf(stderr, "dlopen viewer failed: %s\n", dlerror());
      return 4;
    }
    if (!dlopen(kCG, RTLD_NOW | RTLD_GLOBAL)) {
      fprintf(stderr, "dlopen cypherguard failed: %s\n", dlerror());
      return 4;
    }
    Class capCls = NSClassFromString(@"CPCapsulizedFile");
    Class mgrCls = NSClassFromString(@"CPSecurityLibraryManager");
    if (!capCls || !mgrCls) {
      fprintf(stderr, "viewer classes not loaded\n");
      return 4;
    }

    // --- Security-library init (mirrors app startup) ---
    {
      Class allow = NSClassFromString(@"__CPIR_t_0C8i9vQfEfuH2v");
      SEL regSel = NSSelectorFromString(@"initWTwqPul_VuFSAshq:");
      BOOL regOK = NO;
      if (allow && [allow respondsToSelector:regSel]) {
        BOOL (*f)(id, SEL, id) = (void *)[allow methodForSelector:regSel];
        regOK = f(allow, regSel, kAccessCode());
      }
      Class libCtx = NSClassFromString(@"__CPIR_xuEB8tW4mM4ICMgq");
      SEL initSel = NSSelectorFromString(@"__CPIR_n3ghqzX5ZQuTmaE1");
      SEL getSel = NSSelectorFromString(@"__CPIR_HX7_eOepzyXXqPMU");
      id ctx = nil;
      if (libCtx && [libCtx respondsToSelector:initSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [libCtx performSelector:initSel];
        ctx = [libCtx performSelector:getSel];
#pragma clang diagnostic pop
        if (ctx && [ctx respondsToSelector:@selector(setAroma:)]) {
          void (*setAroma)(id, SEL, char) =
            (void *)[ctx methodForSelector:@selector(setAroma:)];
          setAroma(ctx, @selector(setAroma:), 1);
        }
      }
      id mgr0 = [mgrCls sharedManager];
      for (NSString *s in @[@"__CPIR_8gnYLpUGPL8T1Iht",
                            @"__CPIR_6LurX5PjdM0OlSU5",
                            @"__CPIR_qKA6iTbAya3qEK4o"]) {
        SEL sel = NSSelectorFromString(s);
        if ([mgr0 respondsToSelector:sel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
          [mgr0 performSelector:sel];
#pragma clang diagnostic pop
        }
      }
      if (!regOK || !ctx) {
        fprintf(stderr, "security-library init failed\n");
        return 4;
      }
    }

    // --- Open capsule ---
    id cap = [capCls capsulizedFileWithContentsOfFile:path error:&err];
    if (!cap) {
      fprintf(stderr, "open capsule failed: %s\n",
              err.description.UTF8String ?: "?");
      return 4;
    }

    // --- Unlock with cached license (offline when cached) ---
    id mgr = [mgrCls sharedManager];
    {
      NSError *lerr = nil;
      BOOL (*loadFn)(id, SEL, id, NSError **) = (void *)
        [mgr methodForSelector:@selector(loadServiceToCapsulizedFile:error:)];
      BOOL lok = NO;
      @try {
        lok = loadFn(mgr, @selector(loadServiceToCapsulizedFile:error:),
                     cap, &lerr);
      } @catch (NSException *x) {
        fprintf(stderr, "loadService threw %s: %s\n",
                x.name.UTF8String ?: "?", x.reason.UTF8String ?: "?");
        return 2;
      }
      if (!lok) {
        fprintf(stderr, "loadService failed: %s\n",
                lerr.description.UTF8String ?: "?");
        fprintf(stderr, "Open the book once in DMMbookviewer while online, "
                        "then re-run.\n");
        return 2;
      }
    }
    id lic = [mgr lookupLocalLicenseWithCapsulizedFile:cap error:&err];
    if (!lic) {
      fprintf(stderr, "no local license: %s\n", err.description.UTF8String ?: "?");
      fprintf(stderr, "Open the book once in DMMbookviewer while online, "
                      "then re-run.\n");
      return 2;
    }
    {
      id auth = [cap authentication];
      BOOL (*af)(id, SEL, id, NSError **) =
        (void *)[auth methodForSelector:@selector(applyLicense:error:)];
      NSError *aerr = nil;
      if (!af(auth, @selector(applyLicense:error:), lic, &aerr) ||
          ![[cap authentication] isValid]) {
        fprintf(stderr, "auth applyLicense failed: %s\n",
                aerr.description.UTF8String ?: "?");
        return 3;
      }
    }
    // Key material + unlocked charge variant (mirrors
    // -[__CPIR_3lQGLKUU5g4k0RVq applyLicense:]: fXDk -> 3gCX -> lvQQ).
    @try {
      id fxd = [lic respondsToSelector:NSSelectorFromString(@"__CPIR_fXDktwLZRrPE644h")] ?
        [lic performSelector:NSSelectorFromString(@"__CPIR_fXDktwLZRrPE644h")] : nil;
      SEL cx = NSSelectorFromString(@"__CPIR_3gCXLasSyrMNtB58:");
      if (fxd && [fxd length] == 16 && [cap respondsToSelector:cx]) {
        void (*cf)(id, SEL, id) = (void *)[cap methodForSelector:cx];
        cf(cap, cx, fxd);
      } else {
        fprintf(stderr, "license has no 16-byte key material\n");
        return 3;
      }
      SEL lv = NSSelectorFromString(@"__CPIR_lvQQsXOCAF0pDlss");
      if ([cap respondsToSelector:lv]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [cap performSelector:lv];
#pragma clang diagnostic pop
      }
    } @catch (NSException *x) {
      fprintf(stderr, "license finalize failed: %s\n",
              x.reason.UTF8String ?: "?");
      return 3;
    }

    // --- Extract ---
    NSArray *sums = [cap packagingFilesSummary];
    if (!sums.count) {
      fprintf(stderr, "no entries\n");
      return 4;
    }
    SEL initSel = NSSelectorFromString(@"init");
    id drmV1 = objc_getAssociatedObject(cap,
                                       [cap methodForSelector:initSel]);
    if (!drmV1) {
      fprintf(stderr, "no DRM state\n");
      return 3;
    }
    SEL lz = NSSelectorFromString(@"__CPIR_ncAUAvuBoV0DET98:__CPIR__iXw1isgaCzT5rf8:");
    SEL lp = NSSelectorFromString(@"__CPIR_G2o3_LrUYV1wIPPH:__CPIR__iXw1isgaCzT5rf8:");
    SEL ie = NSSelectorFromString(@"__CPIR_ytjUbJrmpaLBRSSH");
    SEL ip = NSSelectorFromString(@"__CPIR_GzUfGI_IQLFfE3iS");
    SEL mk = NSSelectorFromString(@"initWithLoader_:interpreter:");
    SEL setFS = NSSelectorFromString(@"setFileSummary:");
    SEL od = NSSelectorFromString(@"originalDataWithError:");
    Class decCls = NSClassFromString(@"CPPackagingFileDecryptor");
    [[NSFileManager defaultManager] createDirectoryAtPath:outdir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:NULL];
    NSMutableArray *manifest = [NSMutableArray array];
    NSUInteger ok = 0, fail = 0, i = 0;
    for (id s in sums) {
      NSString *name = [s filename];
      NSString *base = [name lastPathComponent];
      if (!base.length)
        base = [NSString stringWithFormat:@"entry-%lu", (unsigned long)i];
      NSString *dest = [outdir stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"%04lu_%@",
                                                   (unsigned long)i, base]];
      NSData *plain = nil;
      @try {
        SEL ls = [s isZipped] ? lz : lp;
        id (*lf)(id, SEL, unsigned long long, unsigned long long) =
          (void *)[drmV1 methodForSelector:ls];
        id loader = lf(drmV1, ls, (unsigned long long)[s offset],
                       (unsigned long long)[s filesize]);
        SEL is = [s isEncrypted] ? ie : ip;
        id (*gf)(id, SEL) = (void *)[drmV1 methodForSelector:is];
        id interp = gf(drmV1, is);
        id dec = nil;
        if (loader && interp) {
          id (*mf)(id, SEL, id, id) =
            (void *)[decCls instanceMethodForSelector:mk];
          dec = mf([[decCls alloc] init], mk, loader, interp);
          void (*sf)(id, SEL, id) = (void *)[dec methodForSelector:setFS];
          sf(dec, setFS, s);
        }
        if (dec) {
          NSData *(*df)(id, SEL, NSError **) =
            (void *)[dec methodForSelector:od];
          NSError *derr = nil;
          plain = df(dec, od, &derr);
          if (!plain)
            fprintf(stderr, "entry %s: %s\n", base.UTF8String ?: "?",
                    derr.description.UTF8String ?: "?");
        }
      } @catch (NSException *x) {
        fprintf(stderr, "entry %s: exception %s\n", base.UTF8String ?: "?",
                x.reason.UTF8String ?: "?");
      }
      if (!plain || ![plain writeToFile:dest atomically:YES]) {
        fail++; i++; continue;
      }
      ok++;
      [manifest addObject:@{
        @"index": @(i), @"name": name ?: @"",
        @"file": dest.lastPathComponent,
        @"bytes": @(plain.length),
        @"encrypted": @([s isEncrypted]),
        @"expected_size": @([s filesize]),
        @"kind": kindOf(plain),
      }];
      if ((i % 20) == 0) fprintf(stderr, "[%lu/%lu]\n",
                                 (unsigned long)i, (unsigned long)sums.count);
      i++;
    }
    NSData *mj = [NSJSONSerialization dataWithJSONObject:manifest
                                                options:NSJSONWritingPrettyPrinted
                                                  error:NULL];
    [mj writeToFile:[outdir stringByAppendingPathComponent:@"manifest.json"]
         atomically:YES];
    fprintf(stderr, "done: %lu ok, %lu failed -> %s\n",
            (unsigned long)ok, (unsigned long)fail, argv[2]);
    return fail ? 3 : 0;
  }
}
