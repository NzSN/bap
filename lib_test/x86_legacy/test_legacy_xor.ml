open Core_kernel[@@warning "-D"]
open Bap.Std

let bytes hex =
  String.init (String.length hex / 2) ~f:(fun i ->
      Char.of_int_exn (Int.of_string ("0x" ^ String.sub hex ~pos:(2*i) ~len:2)))

let word hex = Word.of_string ("0x" ^ hex ^ ":256u")

let lift hex =
  let memory = Or_error.ok_exn (Memory.create LittleEndian
      (Word.of_int ~width:64 0x401000) (Bigstring.of_string (bytes hex))) in
  Disasm_expert.Basic.with_disasm ~backend:"llvm" "x86_64" ~f:(fun decoder ->
      let decoder = Disasm_expert.Basic.store_asm decoder
                    |> Disasm_expert.Basic.store_kinds in
      match Disasm_expert.Basic.insn_of_mem decoder memory with
      | Ok (consumed, Some insn, `finished) ->
        if Memory.length consumed <> String.length (bytes hex) then
          failwith "decoder consumed the wrong instruction extent";
        X86.X86_lifter.AMD64.lift consumed insn
      | _ -> Or_error.error_string "instruction did not decode completely")
  |> Or_error.ok_exn

let check (name, code, expected) =
  let bil = lift code in
  if List.is_empty bil then failwith (name ^ ": missing legacy lift");
  (match Type.check bil with
   | Ok () -> ()
   | Error _ -> failwith (name ^ ": ill-typed legacy lift"));
  let destination = X86_cpu.AMD64.ymms.(0) in
  let other = X86_cpu.AMD64.ymms.(1) in
  let program = Bil.[
      move destination (int (word "112233445566778899aabbccddeeff000123456789abcdeffedcba9876543210"));
      move other (int (word "ffeeddccbbaa9988776655443322110011111111111111112222222222222222"));
    ] @ bil in
  let result = Stmt.eval program (new Bili.context) in
  match result#lookup destination with
  | Some value ->
    (match Bil.Result.value value with
     | Bil.Imm actual when Word.equal actual (word expected) -> ()
     | _ -> failwith (name ^ ": wrong XOR value or upper-lane behavior"))
  | None -> failwith (name ^ ": destination unavailable")
[@@warning "-D"]

let cases = [
  ("xorps-self", "0f57c0", "112233445566778899aabbccddeeff0000000000000000000000000000000000");
  ("xorps-register", "0f57c1", "112233445566778899aabbccddeeff001032547698badcfedcfe98ba54761032");
  ("xorpd-register", "660f57c1", "112233445566778899aabbccddeeff001032547698badcfedcfe98ba54761032");
  ("vxorps-xmm", "c5f857c1", "000000000000000000000000000000001032547698badcfedcfe98ba54761032");
  ("vxorps-ymm", "c5fc57c1", "eeccee88eeccee00eeccee88eeccee001032547698badcfedcfe98ba54761032");
]

let () =
  match Bap_main.init ~requires:["llvm"] () with
  | Error error ->
    Format.eprintf "%a@." Bap_main.Extension.Error.pp error;
    exit 1
  | Ok () -> List.iter cases ~f:check
