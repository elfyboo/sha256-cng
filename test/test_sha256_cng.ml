(*test vectors obtained from: https://di-mgt.com.au/sha_testvectors.html*)

open Sha256_cng

let repeat_char c n =
  let b = Bytes.create n in
  Bytes.fill b 0 n c;
  Bytes.unsafe_to_string b
;;

let test_str name input expected () =
  let actual = str_exn input in
  Alcotest.(check string) name expected actual
;;

let write_file path content_fn count =
  let oc = open_out_bin path in
  for _ = 1 to count do
    content_fn oc
  done;
  close_out oc
;;

let test_1m_a_str () =
  let input = repeat_char 'a' 1_000_000 in
  Alcotest.(check string)
    "1 million a via str"
    (Sha256_cng.normalize_hex
       "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0")
    (str_exn input)
;;

let test_1m_a_file () =
  let path = Filename.temp_file "sha256_1m_a" ".bin" in
  Fun.protect
    ~finally:(fun () -> Sys.remove path)
    (fun () ->
       write_file path (fun oc -> output_char oc 'a') 1_000_000;
       Alcotest.(check string)
         "1 million a via file"
         (Sha256_cng.normalize_hex
            "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0")
         (file_exn path))
;;

(* requires ~1GB free disk space — opt-in only *)
let test_1gb_repeated () =
  match Sys.getenv_opt "SHA256_TEST_1GB" with
  | None -> ()
  | Some _ ->
    let chunk = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" in
    let path = Filename.temp_file "sha256_1gb" ".bin" in
    Fun.protect
      ~finally:(fun () -> Sys.remove path)
      (fun () ->
         write_file path (fun oc -> output_string oc chunk) 16_777_216;
         Alcotest.(check string)
           "1GB repeated via file"
           (normalize_hex
              "50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e")
           (file_exn path))
;;

let nist_short_tests =
  List.mapi
    (fun i (input, expected) ->
       Alcotest.test_case
         (Printf.sprintf "NIST short %d" i)
         `Quick
         (test_str (Printf.sprintf "NIST short %d" i) input expected))
    Nist_vectors.nist_short_vectors
;;

let run_cli args =
  (* The '2>&1' tells the shell to pipe stderr into stdout *)
  let cmd = Printf.sprintf "dune exec -- sha256-cng %s 2>&1" args in
  let chan = Unix.open_process_in cmd in
  let output = In_channel.input_all chan in
  let status = Unix.close_process_in chan in
  (output, status)

let test_cli_help () =
  let output, status = run_cli "--help" in
  Alcotest.(check bool) "exit success" true (status = Unix.WEXITED 0);
  let trimmed = String.trim output in
  Alcotest.(check bool) "starts with usage" true
    (String.starts_with ~prefix:"usage:" trimmed)

let test_cli_version () =
  let output, status = run_cli "--version" in
  Alcotest.(check bool) "exit success" true (status = Unix.WEXITED 0);
  let trimmed = String.trim output in
  let is_not_empty = String.length trimmed > 0 in
  Alcotest.(check bool) "version not empty" true is_not_empty

let test_cli_string () =
  let output, _ = run_cli "--string abc" in
  let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in
  Alcotest.(check string) "hash matches" (Sha256_cng.normalize_hex expected) (Sha256_cng.normalize_hex output)

let test_cli_empty_string () =
  let output, status = run_cli "--string \"\"" in
  let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in
  Alcotest.(check bool) "exit success" true (status = Unix.WEXITED 0);
  Alcotest.(check string) "empty hash matches" (Sha256_cng.normalize_hex expected) (Sha256_cng.normalize_hex output)

let test_cli_missing_file () =
  let output, status = run_cli "this_file_should_not_exist.txt" in
  Alcotest.(check bool) "exit code 2 for missing file" true (status = Unix.WEXITED 2);
  let trimmed = String.trim output in
  let contains_error = String.starts_with ~prefix:"error:" trimmed in
  Alcotest.(check bool) "error message starts with error:" true contains_error

let test_cli_valid_file () =
  let filename = "___test_abc.txt" in
  let expected_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in
  let oc = open_out filename in
  output_string oc "abc";
  close_out oc;
  Fun.protect
    ~finally:(fun () -> if Sys.file_exists filename then Sys.remove filename)
    (fun () ->
       let output, status = run_cli filename in
       Alcotest.(check bool) "exit success" true (status = Unix.WEXITED 0);
       Alcotest.(check string) "file hash matches" (Sha256_cng.normalize_hex expected_hash) (Sha256_cng.normalize_hex output)
    )

let test_cli_smoke_test () =
  let output, status = run_cli "--smoke-test" in
  Alcotest.(check bool) "smoke test exit success" true (status = Unix.WEXITED 0);
  let message = String.trim output in
  Alcotest.(check string) "smoke test message" "smoke test passed" message

let () =
  Alcotest.run
    "sha256-cng"
    [ ( "NIST FIPS 180-4 vectors"
      , [ Alcotest.test_case
            "empty string"
            `Quick
            (test_str
               "empty string"
               ""
               (Sha256_cng.normalize_hex
                  "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b \
                   7852b855"))
        ; Alcotest.test_case
            "24 bits"
            `Quick
            (test_str
               "24 bits"
               "abc"
               (Sha256_cng.normalize_hex
                  "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 \
                   f20015ad"))
        ; Alcotest.test_case
            "448 bits"
            `Quick
            (test_str
               "448 bits"
               "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
               (Sha256_cng.normalize_hex
                  "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 \
                   19db06c1"))
        ; Alcotest.test_case
            "896 bits"
            `Quick
            (test_str
               "896 bits"
               "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
               (Sha256_cng.normalize_hex
                  "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 \
                   7afee9d1"))
        ] )
    ; ( "large input"
      , [ Alcotest.test_case "1 million a via str" `Slow test_1m_a_str
        ; Alcotest.test_case "1 million a via file" `Slow test_1m_a_file
        ] )
    ; ( "large input opt-in"
      , [ Alcotest.test_case "1GB repeated via file" `Slow test_1gb_repeated ] )
    ; "NIST CAVP short message vectors", nist_short_tests
    ; "CLI", [
      Alcotest.test_case "Help message" `Quick test_cli_help;
        Alcotest.test_case "Prints version" `Quick test_cli_version;
        Alcotest.test_case "String hashing" `Quick test_cli_string;
        Alcotest.test_case "Empty string hashing" `Quick test_cli_empty_string;
        Alcotest.test_case "Missing file" `Quick test_cli_missing_file;
        Alcotest.test_case "Valid file" `Quick test_cli_valid_file;
        Alcotest.test_case "Smoke test success" `Quick test_cli_smoke_test;
      ]
    ]
;;
