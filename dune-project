(lang dune 3.22)

(name sha256-cng)

(generate_opam_files true)

(source
 (github elfyboo/sha256-cng))

(authors "elfyboo" <elfyboo.mail@gmail.com>)

(maintainers "elfyboo" <elfyboo.mail@gmail.com>)

(license Unlicense)

(documentation https://github.com/elfyboo/sha256-cng)

(package
 (name sha256-cng)
 (version "0.1.0")
 (synopsis "SHA-256 hashing for OCaml on Windows via native CNG")
 (description
  "Thin FFI bindings over the Windows CNG (BCrypt) API for computing SHA-256 hashes of files and strings. No dependencies beyond the Windows SDK.")
 (depends
  (ocaml
   (>= 4.08))
  (dune
   (>= 3.22))
  (alcotest :with-test))
 (tags
  (sha256 windows cng bcrypt)))
