
#
# Some common code and data shared among all backends
#

ASM_ENTRY_POINT_PUSH_ENV = 'pusha\n'

ASM_ENTRY_POINT_PUSH_ENV_64 = '''
push rax      ;save current rax
push rbx      ;save current rbx
push rcx      ;save current rcx
push rdx      ;save current rdx
push rbp      ;save current rbp
push rdi      ;save current rdi
push rsi      ;save current rsi
push r8         ;save current r8
push r9         ;save current r9
push r10      ;save current r10
push r11      ;save current r11
push r12      ;save current r12
push r13      ;save current r13
push r14      ;save current r14
push r15      ;save current r15
'''

ASM_ENTRY_POINT_RESTORE_ENV = '''
popa
; clean the stack above, preserve registers accoring to the abi
; we only clean the very bottom, if a patch touches more it has to clean by itself
; we are after_restore: edx is 0 and we need to restore eax, I don't care about eflags
mov eax,  0xbaaaafa0
_clean_stack_loop_entrypoint:
    mov [eax], edx
    add eax, 4
    cmp eax, 0xbaaab000
jne _clean_stack_loop_entrypoint
xor eax, eax
; restore flags
push 0x202
popf
mov DWORD [esp-4], eax
'''

ASM_ENTRY_POINT_RESTORE_ENV_64 = '''
pop r15         ;restore current r15
pop r14         ;restore current r14
pop r13         ;restore current r13
pop r12         ;restore current r12
pop r11         ;restore current r11
pop r10         ;restore current r10
pop r9         ;restore current r9
pop r8         ;restore current r8
pop rsi         ;restore current rsi
pop rdi         ;restore current rdi
pop rbp         ;restore current rbp
pop rdx         ;restore current rdx
pop rcx         ;restore current rcx
pop rbx         ;restore current rbx
pop rax         ;restore current rax

mov rax,  0xbaaaafa0
_clean_stack_loop_entrypoint:
    mov [rax], rdx
    add rax, 4
    cmp rax, 0xbaaab000
    jne _clean_stack_loop_entrypoint
mov rax, 0x202
push rax
xor rax, rax
; restore flags
popfq
mov QWORD [rsp-0x8], rax
'''
