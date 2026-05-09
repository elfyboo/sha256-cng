let normalize_hex s =
  let len = String.length s in
  let b = Bytes.create len in
  let j = ref 0 in
  for i = 0 to len - 1 do
    match s.[i] with
    | ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c' -> ()
    | ('0' .. '9' as c) | ('a' .. 'f' as c) | ('A' .. 'F' as c) ->
      Bytes.set b !j (Char.lowercase_ascii c);
      incr j
    | c -> invalid_arg (Printf.sprintf "normalize_hex: invalid char '%c'" c)
  done;
  Bytes.sub_string b 0 !j
;;

external ocaml_sha256_str_raw : string -> int -> string = "ocaml_sha256_str"
external ocaml_sha256_file_raw : string -> string = "ocaml_sha256_file"

let file_exn path =
  try normalize_hex (ocaml_sha256_file_raw path) with
  | Unix.Unix_error _ as e -> raise e
;;

let file path =
  try Ok (file_exn path) with
  | Unix.Unix_error (e, f, p) -> Error (Unix.Unix_error (e, f, p))
;;

let str_exn s =
  try normalize_hex (ocaml_sha256_str_raw s (String.length s)) with
  | Unix.Unix_error _ as e -> raise e
;;

let str s =
  try Ok (str_exn s) with
  | Unix.Unix_error (e, f, p) -> Error (Unix.Unix_error (e, f, p))
;;
