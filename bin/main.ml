let usage exit_code =
  let msg =
    "usage: sha256-cng <file>\n" ^
    "       sha256-cng --string <input>\n" ^
    "       sha256-cng --smoke-test\n" ^
    "       sha256-cng -v | --version\n" ^
    "       sha256-cng -h | --help"
  in
  prerr_endline msg;
  exit exit_code
;;

let handle_call f arg =
  try
    print_endline (f arg);
    exit 0
  with
  | Unix.Unix_error (e, _, p) ->
      Printf.eprintf "error: %s%s\n" (Unix.error_message e) (if p = "" then "" else ": " ^ p);
      exit 2
  | e ->
      Printf.eprintf "unexpected error: %s\n" (Printexc.to_string e);
      exit 3

let run_smoke_test () =
  let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in
  try
    let actual = Sha256_cng.str_exn "abc" in
    if String.equal actual expected then (
      print_endline "smoke test passed";
      exit 0
    ) else (
      Printf.eprintf "smoke test failed\n  expected: %s\n  got:      %s\n" expected actual;
      exit 1
    )
  with e ->
    Printf.eprintf "smoke test failed: %s\n" (Printexc.to_string e);
    exit 1

let () =
  match Array.to_list Sys.argv with
  | [ _; "-v" ] | [ _; "--version" ] ->
      print_endline Version.version;
      exit 0
  | [ _; "-h" ] | [ _; "--help" ] ->
      usage 0
  | [ _; "--smoke-test" ] ->
      run_smoke_test ()
  | [ _; "--string"; input ] ->
      handle_call Sha256_cng.str_exn input
  | [ _; path ] when not (String.starts_with ~prefix:"-" path) ->
      handle_call Sha256_cng.file_exn path
  | _ ->
      usage 1
