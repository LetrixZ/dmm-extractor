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
//   -> pages in reading order, named after the detected kind, + manifest.json
//      (same names/manifest layout as the Windows backend; see dmmb_win_common.h)
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

// --- Output helpers: mirror dmmb_win_common.h so both backends write the same
// --- names and manifest. Keep these in lockstep with the Windows worker.

// Basename after the last '/' or '\' (mirrors dmmb::OutputName's prefix strip).
static NSString *entryBase(NSString *rawName) {
  NSString *name = rawName ?: @"";
  NSRange r = [name rangeOfCharacterFromSet:
      [NSCharacterSet characterSetWithCharactersInString:@"/\\"]
      options:NSBackwardsSearch];
  return r.location == NSNotFound ? name : [name substringFromIndex:r.location + 1];
}

// "0034.dmmj" -> 34; only purely numeric stems (page ids) qualify.
// Mirrors dmmb::PageId.
static BOOL pageIdOf(NSString *rawName, unsigned long long *out) {
  NSString *base = entryBase(rawName);
  NSRange dot = [base rangeOfString:@"." options:NSBackwardsSearch];
  NSString *stem =
      dot.location == NSNotFound ? base : [base substringToIndex:dot.location];
  if (stem.length == 0 || stem.length > 18) return NO;
  unsigned long long v = 0;
  for (NSUInteger i = 0; i < stem.length; i++) {
    unichar ch = [stem characterAtIndex:i];
    if (ch < '0' || ch > '9') return NO;
    v = v * 10 + (unsigned long long)(ch - '0');
  }
  *out = v;
  return YES;
}

// Reading order: numeric page ids ascending, then any non-numeric names in
// physical order (the physical index breaks ties, matching dmmb::ReadingOrder's
// stable_sort). Mirrors dmmb::ReadingOrder.
static NSArray<NSNumber *> *readingOrderOf(NSArray *sums) {
  NSMutableArray<NSNumber *> *order =
      [NSMutableArray arrayWithCapacity:sums.count];
  for (NSUInteger i = 0; i < sums.count; i++) [order addObject:@(i)];
  [order sortUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
    NSUInteger ia = a.unsignedIntegerValue, ib = b.unsignedIntegerValue;
    unsigned long long pa = 0, pb = 0;
    BOOL va = pageIdOf([sums[ia] filename], &pa);
    BOOL vb = pageIdOf([sums[ib] filename], &pb);
    if (va != vb) return va ? NSOrderedAscending : NSOrderedDescending;
    if (va && pa != pb) return pa < pb ? NSOrderedAscending : NSOrderedDescending;
    if (ia != ib) return ia < ib ? NSOrderedAscending : NSOrderedDescending;
    return NSOrderedSame;
  }];
  return order;
}

// "%04lu_<safe base>": sanitise Windows-invalid characters, trim trailing
// dots/spaces, fall back to entry-<n>, cap the component. Mirrors
// dmmb::OutputName (NSString lengths are UTF-16 code units, like std::wstring).
static NSString *outputNameOf(NSString *rawName, NSUInteger position) {
  NSString *base = entryBase(rawName);
  NSCharacterSet *bad =
      [NSCharacterSet characterSetWithCharactersInString:@"<>:\"/\\|?*"];
  NSMutableString *safe = [NSMutableString stringWithCapacity:base.length];
  for (NSUInteger i = 0; i < base.length; i++) {
    unichar ch = [base characterAtIndex:i];
    [safe appendFormat:@"%C",
        (unichar)((ch < 32 || [bad characterIsMember:ch]) ? (unichar)'_' : ch)];
  }
  base = safe;
  while (base.length && ([base hasSuffix:@"."] || [base hasSuffix:@" "]))
    base = [base substringToIndex:base.length - 1];
  if (!base.length)
    base = [NSString stringWithFormat:@"entry-%lu", (unsigned long)position];
  if (base.length > 200) {
    base = [base substringToIndex:200];
    unichar last = [base characterAtIndex:base.length - 1];
    if (last >= 0xd800 && last <= 0xdbff)
      base = [base substringToIndex:base.length - 1];
  }
  return [NSString stringWithFormat:@"%04lu_%@", (unsigned long)position, base];
}

// Give decrypted images an extension Windows opens by double-click; unknown
// kinds keep the original extension. Mirrors dmmb::WithKindExtension.
static NSString *withKindExtension(NSString *name, NSString *kind) {
  NSString *ext = nil;
  if ([kind isEqualToString:@"jpeg"]) ext = @"jpg";
  else if ([kind isEqualToString:@"png"]) ext = @"png";
  else if ([kind isEqualToString:@"zip"]) ext = @"zip";
  else if ([kind isEqualToString:@"xml"]) ext = @"xml";
  else return name;
  NSRange dot = [name rangeOfString:@"." options:NSBackwardsSearch];
  NSRange sep = [name rangeOfCharacterFromSet:
      [NSCharacterSet characterSetWithCharactersInString:@"/\\"]
      options:NSBackwardsSearch];
  BOOL hasExt = dot.location != NSNotFound && dot.location != 0 &&
                (sep.location == NSNotFound || dot.location > sep.location);
  return hasExt
      ? [[name substringToIndex:dot.location + 1] stringByAppendingString:ext]
      : [name stringByAppendingFormat:@".%@", ext];
}

// Quote/escape exactly like dmmb::Json so manifest.json is byte-identical.
static NSString *jsonString(NSString *s) {
  NSMutableString *out = [NSMutableString stringWithString:@"\""];
  for (NSUInteger i = 0; i < s.length; i++) {
    unichar ch = [s characterAtIndex:i];
    if (ch == '"' || ch == '\\') [out appendFormat:@"\\%C", ch];
    else if (ch < 32) [out appendFormat:@"\\u%04x", (unsigned)ch];
    else [out appendFormat:@"%C", ch];
  }
  [out appendString:@"\""];
  return out;
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
    // Pages come out in reading order (ascending page id) with a kind-based
    // extension; the manifest matches the Windows worker byte for byte.
    NSArray<NSNumber *> *order = readingOrderOf(sums);
    NSMutableString *manifest = [NSMutableString stringWithString:@"[\n"];
    NSUInteger ok = 0, fail = 0;
    for (NSUInteger position = 0; position < order.count; position++) {
      id s = sums[order[position].unsignedIntegerValue];
      NSString *name = [s filename] ?: @"";
      NSString *stem = outputNameOf(name, position);
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
            fprintf(stderr, "entry %s: %s\n", stem.UTF8String ?: "?",
                    derr.description.UTF8String ?: "?");
        }
      } @catch (NSException *x) {
        fprintf(stderr, "entry %s: exception %s\n", stem.UTF8String ?: "?",
                x.reason.UTF8String ?: "?");
      }
      NSString *kind = plain ? kindOf(plain) : nil;
      NSString *file = plain ? withKindExtension(stem, kind) : stem;
      NSString *dest = [outdir stringByAppendingPathComponent:file];
      if (!plain || ![plain writeToFile:dest atomically:YES]) {
        fail++; continue;
      }
      if (ok++) [manifest appendString:@",\n"];
      [manifest appendFormat:
        @"  {\"index\": %lu, \"name\": %@, \"file\": %@, \"bytes\": %lu, "
        @"\"encrypted\": %@, \"expected_size\": %llu, \"kind\": %@}",
        (unsigned long)position, jsonString(name), jsonString(file),
        (unsigned long)plain.length,
        [s isEncrypted] ? @"true" : @"false",
        (unsigned long long)[s filesize], jsonString(kind)];
      if ((position % 20) == 0) fprintf(stderr, "[%lu/%lu]\n",
                                        (unsigned long)position,
                                        (unsigned long)order.count);
    }
    [manifest appendString:@"\n]\n"];
    [manifest writeToFile:[outdir stringByAppendingPathComponent:@"manifest.json"]
               atomically:YES
                 encoding:NSUTF8StringEncoding
                    error:NULL];
    fprintf(stderr, "done: %lu ok, %lu failed -> %s\n",
            (unsigned long)ok, (unsigned long)fail, argv[2]);
    return fail ? 3 : 0;
  }
}
