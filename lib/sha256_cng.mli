(** [normalize_hex s] strips whitespace from [s] and lowercases all hex
    characters. Raises [Invalid_argument] if [s] contains non-hex, non-whitespace
    characters. *)
val normalize_hex : string -> string

(** [file_exn path] returns the lowercase hex-encoded SHA-256 hash of the file at [path].
    @raise Unix.Unix_error if the file cannot be opened or read. *)
val file_exn : string -> string

(** [file path] is the same as {!file_exn} but returns a result instead of raising. *)
val file : string -> (string, exn) result

(** [str_exn input] returns the lowercase hex-encoded SHA-256 hash of [input].
    Binary-safe; null bytes are handled correctly.
    @raise Unix.Unix_error if hashing fails. *)
val str_exn : string -> string

(** [str input] is the same as {!str_exn} but returns a result instead of raising. *)
val str : string -> (string, exn) result
