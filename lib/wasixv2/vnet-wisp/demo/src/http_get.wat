;; Fetches http://10.0.2.2:5001/hello.txt and writes the response to stdout. 10.0.2.2 is the
;; machine's gateway, which the backend reaches as the WISP server's own 127.0.0.1.
;; A failing call exits with `step << 8 | errno`.
(module
  (import "wasixv2" "socket" (func $socket (param i32 i32 i32) (result i32)))
  (import "wasixv2" "connect" (func $connect (param i32 i32 i32) (result i32)))
  (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  ;; sockaddr_in for 10.0.2.2:5001
  (data (i32.const 16) "\02\00\13\89\0a\00\02\02\00\00\00\00\00\00\00\00")
  (data (i32.const 64) "GET /hello.txt HTTP/1.0\r\nHost: localhost\r\n\r\n")

  (func $check (param $v i32) (param $step i32) (result i32)
    (if (i32.lt_s (local.get $v) (i32.const 0))
      (then
        (call $exit_group
          (i32.or (i32.shl (local.get $step) (i32.const 8))
                  (i32.sub (i32.const 0) (local.get $v))))
        unreachable))
    (local.get $v))

  (func (export "_start") (local $fd i32) (local $n i32)
    ;; AF_INET, SOCK_STREAM
    (local.set $fd (call $check (call $socket (i32.const 2) (i32.const 1) (i32.const 0)) (i32.const 1)))
    (drop (call $check (call $connect (local.get $fd) (i32.const 16) (i32.const 16)) (i32.const 2)))
    (drop (call $check (call $write (local.get $fd) (i32.const 64) (i32.const 44)) (i32.const 3)))
    (block $eof
      (loop $more
        (local.set $n (call $check (call $read (local.get $fd) (i32.const 1024) (i32.const 4096)) (i32.const 4)))
        (br_if $eof (i32.eqz (local.get $n)))
        (drop (call $check (call $write (i32.const 1) (i32.const 1024) (local.get $n)) (i32.const 5)))
        (br $more)))
    (call $exit_group (i32.const 0))
    unreachable))
