quickSort:
  push r12
  mov r9d, edx
  mov r12d, ecx
  push rbp
  mov rbp, rdi
  push rbx
  test esi, esi
  js .L9
  lea r12d, [rsi-1]
  xor r9d, r9d
.L9:
  cmp r12d, r9d
  jle .L1
.L12:
  movsx rax, r12d
  mov edx, r12d
  lea ebx, [r9-1]
  movsx rcx, r9d
  lea r10, [rbp+0+rax*8]
  sub edx, r9d
  lea rax, [rbp+0+rcx*8]
  add rdx, rcx
  mov rdi, QWORD PTR [r10]
  lea rsi, [rbp+0+rdx*8]
.L7:
  mov rdx, QWORD PTR [rax]
  cmp rdx, rdi
  jge .L6
  add ebx, 1
  movsx rcx, ebx
  lea rcx, [rbp+0+rcx*8]
  mov r8, QWORD PTR [rcx]
  mov QWORD PTR [rcx], rdx
  mov QWORD PTR [rax], r8
.L6:
  add rax, 8
  cmp rsi, rax
  jne .L7
  movsx rax, ebx
  mov rcx, QWORD PTR [r10]
  mov esi, -1
  mov rdi, rbp
  lea rax, [rbp+8+rax*8]
  mov rdx, QWORD PTR [rax]
  mov QWORD PTR [rax], rcx
  mov ecx, ebx
  mov QWORD PTR [r10], rdx
  mov edx, r9d
  call quickSort
  lea r9d, [rbx+2]
  cmp r12d, r9d
  jg .L12
.L1:
  pop rbx
  pop rbp
  pop r12
  ret