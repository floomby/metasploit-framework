;-----------------------------------------------------------------------------;
; Author: floomby (floomby@nmt.edu)
; Compatible: windows 8
; Size: 
; Build: >build.py single_shell_bind_tcp
;-----------------------------------------------------------------------------;

[BITS 64]
[ORG 0]

  cld
  and rsp, 0xFFFFFFFFFFFFFFF0
  call start
%include "./src/block/block_api.asm"
start:
  pop rbp
%include "./src/block/block_exitfunk.asm"
