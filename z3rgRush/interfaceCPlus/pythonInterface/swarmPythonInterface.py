from dataclasses import dataclass
from cffi import FFI


@dataclass
class RequestSpec:
    url: str
    method: str
    data: str
    payload: str


ffi = FFI()

ffi.cdef("""
typedef struct {
    const char* url;
    const char* method;
    const char* data;
    const char* payload;
} RequestSpecC;

typedef struct {
    RequestSpecC* items;
    int count;
} RequestSpecArray;

RequestSpecArray expandPayloads(
    const char* target,
    const char** wordlist,
    int wordlistCount,
    const char** filetypes,
    int filetypeCount,
    int postData
);

void freeRequestSpecArray(RequestSpecArray arr);

const char** rotateHeaders(
    int rotationIndex,
    const char** userAgents, int userAgentsCount,
    const char** acceptHeaders, int acceptHeadersCount,
    const char** acceptLanguages, int acceptLanguagesCount,
    const char** acceptEncodings, int acceptEncodingsCount,
    const char** referers, int referersCount,
    const char** secFetchDest, int secFetchDestCount,
    const char** secFetchMode, int secFetchModeCount,
    const char** secFetchSite, int secFetchSiteCount,
    const char** secCHUAMobile, int secCHUAMobileCount,
    const char** secCHUAPlatform, int secCHUAPlatformCount
);
void freeRotatedHeaders(const char** headers);
""")


def loadNativeLibrary():
    return ffi.dlopen("native/build/libswarmCore.so")
