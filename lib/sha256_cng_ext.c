#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/unixsupport.h>
#include <caml/threads.h>
//
#include <windows.h>
//
#include <minwindef.h>
//
#include <bcrypt.h>
//
#include <limits.h> // Required for ULONG_MAX
#define SHA256_BYTE_LEN 32
#define HEX_CHARS_PER_BYTE 2
#define SHA256_HEX_LEN ((SHA256_BYTE_LEN * HEX_CHARS_PER_BYTE) + 1)
#define CHUNK_SIZE_BYTES 65536
#define ERR_STR_BUFFER_LEN 256
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define HIGH_NIBBLE_SHIFT 4
#define LOW_NIBBLE_MASK 0x0F
#define SHA256_ERR_FILE_NOT_FOUND ENOENT
#define SHA256_ERR_ACCESS_DENIED EACCES
#define SHA256_ERR_FILE_IN_USE EBUSY
#define SHA256_ERR_UNKNOWN ENOSYS

static void raise_sha256_error(DWORD win_err, const char *path) {
  int code;
  switch (win_err) {
  case ERROR_FILE_NOT_FOUND:
  case ERROR_PATH_NOT_FOUND:
    code = SHA256_ERR_FILE_NOT_FOUND;
    break;
  case ERROR_ACCESS_DENIED:
    code = SHA256_ERR_ACCESS_DENIED;
    break;
  case ERROR_SHARING_VIOLATION:
    code = SHA256_ERR_FILE_IN_USE;
    break;
  default:
    code = SHA256_ERR_UNKNOWN;
    break;
  }
  unix_error(code, "sha256_cng", caml_copy_string(path));
}

typedef struct {
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
  PBYTE pbHashObject;
  PBYTE pbHash;
  DWORD cbHash;
} SHA256_CTX;

typedef struct {
  const unsigned char *data;
  ULONG len;
} str_input;

static const char hex_table[] = "0123456789abcdef";

/* branchless hex encoding via lookup table */
static void to_hex(PBYTE hash, char *out) {
  for (int i = 0; i < SHA256_BYTE_LEN; i += 1) {
    out[i * HEX_CHARS_PER_BYTE] = hex_table[hash[i] >> HIGH_NIBBLE_SHIFT];
    out[i * HEX_CHARS_PER_BYTE + 1] = hex_table[hash[i] & LOW_NIBBLE_MASK];
  }
  out[SHA256_HEX_LEN - 1] = '\0';
}

/* BCryptHashData wrapper. cast to PBYTE is safe, BCrypt treats input as
 * read-only */
static NTSTATUS perform_hash(BCRYPT_HASH_HANDLE hHash,
                             const unsigned char *data, ULONG len) {
  return BCryptHashData(hHash, (PBYTE)data, len, 0);
}

/* feeder callback type — called by run_sha256_generic to supply input data */
typedef NTSTATUS (*sha256_feeder)(BCRYPT_HASH_HANDLE hHash, void *user_data);

static NTSTATUS feed_string(BCRYPT_HASH_HANDLE hHash, void *user_data) {
  str_input *hStr = (str_input *)user_data;
  return perform_hash(hHash, hStr->data, hStr->len);
}

/* streams file in 64kb chunks to keep memory usage flat */
static NTSTATUS feed_file(BCRYPT_HASH_HANDLE hHash, void *user_data) {
  HANDLE hFile = *(HANDLE *)user_data;
  BYTE buffer[CHUNK_SIZE_BYTES];
  DWORD bytesRead = 0;
  NTSTATUS status = STATUS_SUCCESS;

  while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) &&
         bytesRead > 0) {
    status = perform_hash(hHash, buffer, bytesRead);
    if (!BCRYPT_SUCCESS(status)) {
      break;
    }
  }
  return status;
}

static NTSTATUS init_sha256(SHA256_CTX *ctx) {
  DWORD cbHashObject, cbData;
  ctx->hAlg = NULL;
  ctx->hHash = NULL;
  ctx->pbHashObject = NULL;
  ctx->pbHash = NULL;

  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status)) {
    return status;
  }

  status = BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH,
                             (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
  if (!BCRYPT_SUCCESS(status)) {
    return status;
  }

  status = BCryptGetProperty(ctx->hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&ctx->cbHash,
                             sizeof(DWORD), &cbData, 0);
  if (!BCRYPT_SUCCESS(status)) {
    return status;
  }

  ctx->pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
  ctx->pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbHash);

  if (!ctx->pbHashObject || !ctx->pbHash) {
    return STATUS_UNSUCCESSFUL;
  }

  return BCryptCreateHash(ctx->hAlg, &ctx->hHash, ctx->pbHashObject,
                          cbHashObject, NULL, 0, 0);
}

static void free_sha256(SHA256_CTX *ctx) {
  if (ctx->hHash) {
    BCryptDestroyHash(ctx->hHash);
  }
  if (ctx->hAlg) {
    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
  }
  if (ctx->pbHashObject) {
    HeapFree(GetProcessHeap(), 0, ctx->pbHashObject);
  }
  if (ctx->pbHash) {
    HeapFree(GetProcessHeap(), 0, ctx->pbHash);
  }
}

static NTSTATUS run_sha256_generic(sha256_feeder feeder, void *user_data,
                                   char hex_out[SHA256_HEX_LEN]) {
  SHA256_CTX ctx;
  NTSTATUS status = init_sha256(&ctx);
  if (!BCRYPT_SUCCESS(status)) {
    free_sha256(&ctx);
    return status;
  }

  status = feeder(ctx.hHash, user_data);

  if (BCRYPT_SUCCESS(status)) {
    status = BCryptFinishHash(ctx.hHash, ctx.pbHash, ctx.cbHash, 0);
    if (BCRYPT_SUCCESS(status)) {
      to_hex(ctx.pbHash, hex_out);
    }
  }

  free_sha256(&ctx);
  return status;
}

static NTSTATUS run_sha256_str(const unsigned char *data, ULONG len,
                               char hex_out[SHA256_HEX_LEN]) {
  str_input in = {data, len};
  return run_sha256_generic(feed_string, &in, hex_out);
}

static NTSTATUS run_sha256_file(HANDLE hFile, char hex_out[SHA256_HEX_LEN]) {
  return run_sha256_generic(feed_file, &hFile, hex_out);
}

/*
 * ocaml_sha256_str: hash an arbitrary byte string.
 * String_val and Int_val are extracted before any allocation so the GC
 * cannot move v_str while data is in use.
 */
CAMLprim value ocaml_sha256_str(value v_str, value v_len) {
  CAMLparam2(v_str, v_len);
  CAMLlocal1(v_hash);

  /*
   * Following OCaml convention: Use Long_val to extract the unboxed integer
   * from the OCaml value. Note that on Windows (LLP64), 'long' is 32-bit,
   * which effectively limits in-memory string hashing to ~2GB.
   */
  long len = Long_val(v_len);

  /*
   * Simple safety check:
   * Since OCaml ints are signed, we check for < 0
   */
  if (len < 0) {
    caml_invalid_argument("sha256_cng: invalid string length");
  }

  const unsigned char *data = (const unsigned char *)String_val(v_str);
  char hex_digest[SHA256_HEX_LEN] = {0};

  NTSTATUS status = run_sha256_str(data, (unsigned long)len, hex_digest);
  if (!BCRYPT_SUCCESS(status)) {
    raise_sha256_error(status, "internal_string_buffer");
  }

  v_hash = caml_copy_string(hex_digest);
  CAMLreturn(v_hash);
}

/*
 * ocaml_sha256_file: hash a file by path.
 * File handle is closed before raising so no handle is leaked on error.
 */
CAMLprim value ocaml_sha256_file(value v_path) {
  CAMLparam1(v_path);
  CAMLlocal1(v_hash);

  // after caml_release_runtime_system() the GC can run and move v_path, invalidating path
  //const char *path = String_val(v_path);
  // fix: copy path to a local buffer before releasing the runtime system
  char c_path[MAX_PATH];
  strncpy(c_path, String_val(v_path), MAX_PATH - 1);
  c_path[MAX_PATH - 1] = '\0';

  char hex_digest[SHA256_HEX_LEN] = {0};

  HANDLE hFile = CreateFileA(c_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hFile == INVALID_HANDLE_VALUE) {
    raise_sha256_error(GetLastError(), c_path);
  }

  /* allow other OCaml threads to run while windows hashes the file */
  /* Docs: "...until caml_acquire_runtime_system() is called, the C code must not access any OCaml data, nor call any function of the run-time system, nor call back into OCaml code" */
  caml_release_runtime_system();
  NTSTATUS status = run_sha256_file(hFile, hex_digest);
  CloseHandle(hFile);
  caml_acquire_runtime_system();

  if (!BCRYPT_SUCCESS(status)) {
    raise_sha256_error(status, c_path);
  }

  v_hash = caml_copy_string(hex_digest);
  CAMLreturn(v_hash);
}
