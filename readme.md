# sha256-cng

SHA-256 hashing for OCaml on Windows via the native CNG (BCrypt) API. No external dependencies or bundled binaries.

## Usage

```ocaml
(* hash a file — raises Unix.Unix_error on failure *)
let hash = Sha256_cng.file_exn "C:\\path\\to\\file.txt"

(* hash a file — returns a result *)
let hash = Sha256_cng.file "C:\\path\\to\\file.txt"

(* hash a string — binary-safe, handles null bytes, — raises Unix.Unix_error on failure *)
let hash = Sha256_cng.str_exn "hello"

(* hash a string — returns a result *)
let hash = Sha256_cng.str "hello"
```

Errors use standard Unix error codes:

```ocaml
match Sha256_cng.file "C:\\path\\to\\file.txt" with
| Ok hash -> ...
| Error (Unix.Unix_error (e, _, _)) ->
  match e with
  | Unix.ENOENT  -> (* file not found *)
  | Unix.EACCES  -> (* permission denied *)
  | Unix.EBUSY   -> (* file in use *)
  | _            -> (* other error *)
```

## CLI

```bash
sha256-cng <filepath>
sha256-cng --string <input>
sha256-cng --smoke-test
sha256-cng -v | --version
sha256-cng -h | --help
```

## Requirements

- Windows
- OCaml >= 4.13
- dune >= 3.22

## Installation
sha256 can be installed from the official opam-repository.

```bash
opam install sha256-cng
```

## Testing

```bash
dune runtest
```

Tests include NIST FIPS 180-4 short message vectors, NIST CAVP byte-oriented vectors, file boundary conditions, and error path coverage.

To run the optional 1GB streaming test (requires ~1GB free disk space):

```bash
opam exec --set-env SHA256_TEST_1GB=1 -- dune runtest
```

## Why

Uses Windows CNG directly rather than a third-party C library or pure OCaml implementation, avoiding additional runtime dependencies on Windows.
