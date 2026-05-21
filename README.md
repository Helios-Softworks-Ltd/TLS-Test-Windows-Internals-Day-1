\# TLS Test — Windows Internals Day 1



A small project poking at Thread Local Storage on Windows, both through the documented Win32 API and by reversing the underlying `RtlTlsAlloc` inside ntdll.



\## What is TLS?



Thread Local Storage is a mechanism for giving each thread its own private copy of a variable. Same name, same "slot," different value per thread. The classic use case is anything that needs to be globally accessible from any function but must not be shared between threads — things like the last error code, per-thread caches, or pointers to per-thread state.



On Windows there are a few ways to get at it:



\- \*\*The Win32 TLS API\*\* — `TlsAlloc`, `TlsSetValue`, `TlsGetValue`, `TlsFree`. You ask the OS for a slot index, then read and write into that slot per thread.

\- \*\*The `thread\_local` keyword\*\* — C++ language-level TLS. The compiler and runtime do the bookkeeping for you; you just declare a variable `thread\_local` and every thread gets its own.

\- \*\*Compiler intrinsics like `\_\_declspec(thread)`\*\* — the older MSVC-specific way of doing what `thread\_local` now does.



Under the hood, all of these eventually touch the same OS structures: the TEB (Thread Environment Block), which holds a per-thread array of TLS slots, and the PEB (Process Environment Block), which holds the bitmaps tracking which slot indices are allocated process-wide.



\## The tests



`source.cpp` runs two small tests covering the two main approaches.



\### Test one — Win32 TLS API



Walks the full lifecycle:



1\. `TlsAlloc` asks the OS for a free slot and gives back an index. If everything's already taken it returns `TLS\_OUT\_OF\_INDEXES`.

2\. `TlsSetValue` stores a `void\*` into that slot for the current thread. The test stuffs the integer `42` into it via `reinterpret\_cast<LPVOID>` because the API takes a pointer-sized value.

3\. `TlsGetValue` reads it back out, again for the current thread.

4\. `TlsFree` releases the index so another part of the program (or another DLL) can claim it.



Expected output: `TLS value: 42`.



\### Test two — `thread\_local`



Same idea in one line. The compiler and CRT handle allocation, storage, and cleanup; you just use the variable like any other.



Expected output: `Thread local value: 42`.



Both tests run on a single thread, so the "per thread" aspect isn't really exercised — the point here is to confirm the APIs work end to end and to set the stage for the reverse engineering below.



\## Reverse Engineering



I could start this with what i already know about TLS but that would take out the fun from reversing. So for that reason i am going to start within `KernelBase.dll` looking for `TlsAlloc`.



> https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc



```c

DWORD \_\_stdcall TlsAlloc()

{

&#x20; int v0; // eax

&#x20; DWORD v2; // \[rsp+30h] \[rbp+8h] BYREF



&#x20; v2 = 0;

&#x20; v0 = RtlTlsAlloc(\&v2);

&#x20; if ( v0 >= 0 )

&#x20;   return v2;

&#x20; BaseSetLastNTError((unsigned int)v0);

&#x20; return -1;

}

```



After a quick review I could tell this won't be much help as this seems to just be a wrapper for `RtlTlsAlloc` which is located within `ntdll.dll`. ntdll is the lowest point within the usermode space and handles the calls into the kernel space (syscalls).



\### Why is the call we need there?



ntdll has no dependencies of its own, so it can be loaded into processes very early — before the rest of the system is even up. A good example of this is `autochk.exe`; autochk is required to run before the system is logged in, meaning if it had any dependencies it would be an issue. This is also plainly called a \*native process\*.



\### Before we hit the decompile



\*\*The two-tier TLS layout\*\*



Windows gives each thread a small fast array of TLS slots and a larger lazy one:



\- `TEB->TlsSlots\[64]` — the primary 64 slots, always present.

\- `TEB->TlsExpansionSlots` — pointer to a 1024-slot array (8KB = 1024 × 8 bytes), heap-allocated on first use.



The PEB tracks which slot indices are taken using two separate bitmaps:



\- `PEB->TlsBitmap` — 64 bits for the primary array.

\- `PEB->TlsExpansionBitmap` — 1024 bits for the expansion array.



Total: indices 0–63 live in primary, 64–1087 live in expansion. That's why at the end you'll see `+ 64` — translating an expansion-bitmap bit position into a global TLS index.



\### The decompile



Within ntdll.dll after we have located the `RtlTlsAlloc` function you will see this:



```c

\_\_int64 \_\_fastcall RtlTlsAlloc(\_DWORD \*return\_tls\_index)

{

&#x20; struct \_TEB \*teb; // rdi

&#x20; \_PEB \*peb; // rbp

&#x20; \_RTL\_BITMAP \*TlsBitmap; // r11

&#x20; int v5; // r10d

&#x20; unsigned int v6; // esi

&#x20; \_QWORD \*v7; // r9

&#x20; \_\_int64 \*v8; // rbx

&#x20; \_\_int64 i; // rax

&#x20; unsigned int v10; // ebx

&#x20; void \*\*TlsExpansionSlots; // rsi

&#x20; \_RTL\_BITMAP \*TlsExpansionBitmap; // r10

&#x20; int v13; // r9d

&#x20; unsigned int v14; // r11d

&#x20; \_\_int64 v15; // rax

&#x20; \_QWORD \*v16; // r8

&#x20; \_\_int64 \*v17; // rbx

&#x20; \_\_int64 j; // rax

&#x20; \_\_int64 v19; // rbx

&#x20; unsigned int v21; // ebx

&#x20; void \*\*v22; // rax

&#x20; void \*\*v23; // rbx



&#x20; teb = NtCurrentTeb();

&#x20; peb = teb->ProcessEnvironmentBlock;

&#x20; while ( 1 )

&#x20; {

&#x20;   RtlEnterCriticalSection(\&FastPebLock);

&#x20;   TlsBitmap = peb->TlsBitmap;

&#x20;   v5 = (TlsBitmap->Buffer \& 4) != 0 ? 0x20 : 0;

&#x20;   v6 = v5 + TlsBitmap->SizeOfBitMap - 1;

&#x20;   v7 = (TlsBitmap->Buffer - ((TlsBitmap->Buffer \& 4) != 0 ? 4 : 0));

&#x20;   if ( TlsBitmap->SizeOfBitMap )

&#x20;   {

&#x20;     v8 = (TlsBitmap->Buffer - ((TlsBitmap->Buffer \& 4) != 0 ? 4 : 0));

&#x20;     for ( i = \*v7 | ((1LL << v5) - 1); i == -1; i = \*v8 )

&#x20;     {

&#x20;       if ( ++v8 > \&v7\[v6 >> 6] )

&#x20;         goto LABEL\_8;

&#x20;     }

&#x20;     \_BitScanForward64(\&i, \~i);

&#x20;     v10 = i + ((v8 - v7) << 6);

&#x20;     if ( v10 != -1 \&\& v10 <= v6 )

&#x20;     {

&#x20;       v19 = v10 - v5;

&#x20;       if ( v19 != -1 )

&#x20;       {

&#x20;         RtlSetBits(TlsBitmap, v19, 1);

&#x20;         RtlLeaveCriticalSection(\&FastPebLock);

&#x20;         teb->TlsSlots\[v19] = 0;

LABEL\_17:

&#x20;         \*return\_tls\_index = v19;

&#x20;         return 0;                             // STATUS\_SUCCESS

&#x20;       }

&#x20;     }

&#x20;   }

LABEL\_8:

&#x20;   TlsExpansionSlots = teb->TlsExpansionSlots;

&#x20;   if ( TlsExpansionSlots )

&#x20;     break;

&#x20;   RtlLeaveCriticalSection(\&FastPebLock);

&#x20;   v22 = RtlpTlsHeapAlloc();

&#x20;   v23 = v22;

&#x20;   if ( !v22 )

&#x20;     return 0xC0000017LL;                      // STATUS\_NO\_MEMORY

&#x20;   memset\_thunk\_772440563353939046(v22, 0, 0x2000u);

&#x20;   teb->TlsExpansionSlots = v23;

&#x20; }

&#x20; TlsExpansionBitmap = peb->TlsExpansionBitmap;

&#x20; v13 = (TlsExpansionBitmap->Buffer \& 4) != 0 ? 0x20 : 0;

&#x20; v14 = v13 + TlsExpansionBitmap->SizeOfBitMap - 1;

&#x20; v15 = (TlsExpansionBitmap->Buffer \& 4) != 0 ? 4 : 0;

&#x20; v16 = (TlsExpansionBitmap->Buffer - v15);

&#x20; if ( !TlsExpansionBitmap->SizeOfBitMap )

&#x20;   goto LABEL\_19;

&#x20; v17 = (TlsExpansionBitmap->Buffer - v15);

&#x20; for ( j = \*v16 | ((1LL << v13) - 1); j == -1; j = \*v17 )

&#x20; {

&#x20;   if ( ++v17 > \&v16\[v14 >> 6] )

&#x20;     goto LABEL\_19;

&#x20; }

&#x20; \_BitScanForward64(\&j, \~j);

&#x20; v21 = j + ((v17 - v16) << 6);

&#x20; if ( v21 <= v14 )

&#x20; {

&#x20;   if ( v21 != -1 )

&#x20;   {

&#x20;     v21 -= v13;

&#x20;     if ( v21 != -1 )

&#x20;       RtlSetBits(peb->TlsExpansionBitmap, v21, 1);

&#x20;   }

&#x20; }

&#x20; else

&#x20; {

LABEL\_19:

&#x20;   v21 = -1;

&#x20; }

&#x20; RtlLeaveCriticalSection(\&FastPebLock);

&#x20; if ( v21 != -1 )

&#x20; {

&#x20;   TlsExpansionSlots\[v21] = 0;

&#x20;   LODWORD(v19) = v21 + 64;

&#x20;   goto LABEL\_17;

&#x20; }

&#x20; return 0xC0000017LL;                          // STATUS\_NO\_MEMORY

}

```



I have added simple comments for the NTSTATUS errors.



\### Walking through it



At a high level the function does this:



1\. Try to find a free slot in the primary bitmap. Return it if found.

2\. If the primary is full, make sure this thread has an expansion slot array. If it doesn't, allocate one and loop back to step 1.

3\. Try to find a free slot in the expansion bitmap. Return it (+ 64) if found, otherwise return `STATUS\_NO\_MEMORY`.



Both scans are the same algorithm running on a different bitmap, which is why the second half looks like a near-copy of the first.



\#### The outer `while(1)` loop



Only iterates more than once in one specific case: primary is full \*and\* this thread hasn't allocated its expansion slots yet. The function drops the PEB lock (you can't call the heap while holding it), heap-allocs the 8KB expansion array, stores it in the TEB, then loops back to retry from the top — because another thread could've freed a primary slot while we were unlocked, so it's worth re-scanning the primary first.



\#### The first scan: primary bitmap



```c

v5 = (TlsBitmap->Buffer \& 4) != 0 ? 0x20 : 0;

v7 = TlsBitmap->Buffer - ((TlsBitmap->Buffer \& 4) != 0 ? 4 : 0);

```



This is the alignment hack and it's the part nobody catches first time. The buffer is `PULONG` (4-byte aligned), but the loop wants to scan 64 bits at a time using `\_BitScanForward64`. If the buffer happens to sit 4 bytes off an 8-byte boundary, the code:



\- backs the pointer up by 4 so it's 8-byte aligned (`v7 = Buffer - 4`),

\- sets `v5 = 32` to remember those 32 bits of padding,

\- OR's `(1LL << 32) - 1` = `0xFFFFFFFF` into the first qword it reads, so the 32 phantom bits look "used" and the scan won't try to hand one out.



Later, `v19 = v10 - v5` subtracts the phantom bits back off to get the real slot index.



The scan loop itself:



```c

for ( i = \*v7 | ((1LL << v5) - 1); i == -1; i = \*v8 ) { ... }

\_BitScanForward64(\&i, \~i);

```



Walk the buffer one qword at a time. `i == -1` means "all 64 bits set, slot fully used", skip it. Once a qword has at least one zero bit, invert it so free bits become 1s, then `\_BitScanForward64` finds the index of the lowest set bit. Add the qword's offset (`(v8 - v7) << 6` — shifting by 6 because 2⁶ = 64 bits per qword) and you have the absolute bit position.



If it found one, `RtlSetBits` marks it as used, the lock is released, the slot in the TEB is zeroed, and the index is returned via `\*return\_tls\_index`.



\#### The fallback: making sure expansion storage exists



```c

LABEL\_8:

&#x20;   TlsExpansionSlots = teb->TlsExpansionSlots;

&#x20;   if ( TlsExpansionSlots ) break;

&#x20;   RtlLeaveCriticalSection(\&FastPebLock);

&#x20;   v22 = RtlpTlsHeapAlloc();

&#x20;   ...

&#x20;   memset\_thunk\_...(v22, 0, 0x2000u);   // memset to 0, 0x2000 = 8KB = 1024 \* 8 bytes

&#x20;   teb->TlsExpansionSlots = v23;

```



The bitmap is process-wide (all threads agree on which indices are allocated), but the actual storage for the values is per-thread. Each thread allocates its own expansion array the first time it crosses into the expansion tier. The `memset\_thunk\_...` is just `memset` zeroing the 8KB — one pointer per slot, 1024 slots.



\#### The second scan: expansion bitmap



Same alignment trick, same scan loop, same set-bit-and-return pattern. The only real difference is at the very end:



```c

LODWORD(v19) = v21 + 64;

goto LABEL\_17;

```



The expansion bitmap's bit 0 corresponds to TLS index 64, bit 1 to 65, and so on. The `+ 64` turns the bitmap-local position into the global TLS index that callers use with `TlsGetValue` / `TlsSetValue`. Then it falls into the shared return point both success paths use.



If neither bitmap had a free bit, you're out of slots entirely and the function returns `STATUS\_NO\_MEMORY`.



\---



\*Note: this post is not AI, but it was re-written to be more understandable by AI.\*

