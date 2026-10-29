+++
title = "Intercepting CPUID Without a Hypervisor"
date = 2026-10-29
+++

## Introduction

A common assumption is that you need a hypervisor to intercept CPUID on Intel CPUs. I used to believe that’s the only way as well, but I was pointed out that there is another one, and I went down the rabbit hole. A semi-undocumented MSR described in [2012 Intel VT FlexMigration application note](https://www.intel.com/content/www/us/en/content-details/671288/intel-virtualization-technology-flexmigration-intel-vt-flexmigration-application-note.html) enables CPUID faulting: when MSR_MISC_FEATURES_ENABLES (0x140) bit 0 is set, executing CPUID at CPL > 0 raises a #GP exception that lets you trap and manually handle it without running a hypervisor.

![intercepting_cpuid_without_a_hypervisor-1](/images/posts/intercepting_cpuid_without_a_hypervisor-1.png)

CPUID faulting has been available since Ivy Bridge CPUs (2012), yet this MSR is undocumented in the Intel SDM. That’s probably why after all my research I only found it mentioned a couple of times in KVM and Linux kernel mailing list threads about fixing odd behavior related to it. Linux supports it as a feature through arch_prctl(ARCH_SET_CPUID) but I haven’t seen any implementation of it in Windows.

Honestly, I don’t think it has many practical use cases given the limitations mentioned below. What makes it interesting is that most people take it for granted that CPUID VM exits are unconditional on Intel, and as I’ll show later in the post, that assumption isn’t always true, and in some obscure cases it can take your whole system down as seen in [this KVM thread](https://lkml.iu.edu/hypermail/linux/kernel/1903.3/00781.html).

## Limitations

- CPUID faulting is limited to CPL > 0 (no kernel mode faulting).
- PatchGuard monitors the IDT. If it detects tampering, it triggers a bug check (BSOD), meaning bypassing it is required which is out of scope for this post.
- VBS/HVCI also prevents writing to the IDT.
- Intel Ivy Bridge and above only. AMD has a similar mechanism, but I don’t own an AMD machine, so it hasn’t been tested.
- Detectable via timing attacks as exception handling costs roughly the same as a VM exit (~1000 cycles).

## Exception Handling Mechanism

At a high level, when an exception occurs in user mode, the CPU switches to kernel mode and dispatches it through an array of handlers named the IDT (Interrupt Descriptor Table). Each entry in this table points to a handler for a specific exception.

![intercepting_cpuid_without_a_hypervisor-2](/images/posts/intercepting_cpuid_without_a_hypervisor-2.png)

IDT[13] is the #GP handler, which is where the execution lands when a general protection fault occurs. A #GP can be triggered by many things in user mode such as executing a privileged instruction like RDMSR, accessing a restricted I/O port, trying to execute a kernel address, or in our case, executing CPUID with faulting enabled. By hooking that entry with our own handler, we can intercept the fault, determine whether it was triggered by a CPUID instruction in CPL 3, and if so, return arbitrary registers back to user mode.

While the #GP handler is same across all logical processors (KiGeneralProtectionFault), each logical processor has its own IDT loaded via the IDTR register. We need hook the #GP entry on each logical processor individually.

![intercepting_cpuid_without_a_hypervisor-3](/images/posts/intercepting_cpuid_without_a_hypervisor-3.png)

## Implementation

IDT is read-only, so we need a way to write to it. There are easier ways to do this, but I went with MmMapIoSpaceEx, which lets you remap a physical page with different permissions. By getting the physical address of the IDT entry with MmGetPhysicalAddress and remapping it as RW with MmMapIoSpaceEx, we get a writable pointer to the entry without touching the original permissions and store it in a global array. We do the remapping beforehand rather than inside the IPI callback because MmMapIoSpaceEx requires IRQL ≤ DISPATCH_LEVEL, while IPIs run at IRQL_IPI_LEVEL, so it can’t be called from within one.

```cpp,linenos
cpu_count = KeQueryActiveProcessorCount( nullptr );
for ( SIZE_T i = 0; i < cpu_count; ++i )
{
    KAFFINITY original = KeSetSystemAffinityThreadEx( 1ULL << i );
    segment_descriptor_register_64 idtr;
    __sidt( &idtr ); // load idt of each processor
    // get #GP entry at IDT[13]
    segment_descriptor_interrupt_gate_64* gp_entry = ( segment_descriptor_interrupt_gate_64* )idtr.base_address + general_protection;
    if ( first )
    {
        // #GP entry points to KiGeneralProtectionFault in all cpus
        original_gp_handler = read_idt_entry( gp_entry );
        first = false;
    }
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress( gp_entry );
    if ( !phys.QuadPart )
    {
        for ( SIZE_T j = 0; j < i; ++j )
        {
            if ( gp_entries[ j ] )
            {
                MmUnmapIoSpace( gp_entries[ j ], sizeof( segment_descriptor_interrupt_gate_64 ) );
                gp_entries[ j ] = nullptr;
            }
        }
        KeRevertToUserAffinityThreadEx( original );
        return false;
    }
    // remap a read only page to write on it
    gp_entries[ i ] = ( segment_descriptor_interrupt_gate_64* )MmMapIoSpaceEx( phys, sizeof( segment_descriptor_interrupt_gate_64 ), PAGE_READWRITE );
}
```

Once we have the writable addresses to each logical processors #GP entry, we fire an IPI to hook the handler on all logical processors, and set bit 0 of MSR_MISC_FEATURES_ENABLES (0x140) to enable CPUID faulting.

```cpp,linenos
ULONG_PTR hook_gp_handler( ULONG_PTR context )
{
    UNREFERENCED_PARAMETER( context );
    ULONG cpu_index = KeGetCurrentProcessorIndex( );
    // writing idt entry to our custom handler
    write_idt_entry( gp_entries[ cpu_index ], ( UINT64 )gp_handler_stub );
    // enabling cpuid faulting for CPL > 0
    UINT64 msr = __readmsr( MSR_MISC_FEATURES_ENABLES );
    msr |= 1ULL;
    __writemsr( MSR_MISC_FEATURES_ENABLES, msr );
    return 0;
}
```

Now that we hooked the original handler, let’s walk through our handler.

```asm,linenos
; stack frame
; [rsp + 0] error_code
; [rsp + 8] rip
; [rsp + 16] cs 0 = kernel, 3 = user
; [rsp + 24] rflags
; [rsp + 32] rsp
; [rsp + 40] ss
PUBLIC gp_handler_stub
gp_handler_stub PROC
    test byte ptr[rsp + 16], 3
    jnz is_user_mode
    jmp qword ptr [original_gp_handler]; cpl is 0, not our exception, let the original handler handle it
```

When the CPU transfers control to our handler, the stack frame is pushed by the CPU itself. The first thing we do is check the CS field at [rsp + 16]. The lower two bits are the CPL. If the bits are zero, the exception came from kernel mode and is not ours to handle, so we jump to the original KiGeneralProtectionFault handler. If the CPL is 3, we know it came from user mode and continue.

```asm,linenos
is_user_mode:
    swapgs ; switch to kernel gs
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax
    mov rbp, rsp
    mov rcx, rbp ; pass regs as the first argument to gp_handler
    mov rdx, [rbp+80h] ; move faulting rip to rdx
    mov rax, 00007FFFFFFFFFFEh
    cmp rdx, rax
    ja not_cpuid ; rip is a kernel space address attempted to execute in usermode, resulting in #GP, not our exception
    stac ; disable smap to read an usermode page in kernelmode
    movzx r8d, word ptr [rdx]
    clac ; re-enable smap
    cmp r8d, 0A20Fh ; check if faulting rip is cpuid instruction, if not its not our exception, let the original handler handle it
    jne not_cpuid
    sub rsp, 20h
    call gp_handler ; handle cpuid call
    add rsp, 20h
```

Once we confirm the fault came from user mode, we call swapgs to switch to the kernel GS, then save all GPRs onto the stack, giving us a reg_context struct that we pass to the C handler later. Then, we check whether the faulting RIP is a user mode address. A kernel space address can also trigger #GP when executed at CPL 3, so we check if it’s above the upper boundary of user space. If it’s above that, it’s not our exception to handle and we jump to not_cpuid to forward to the original handler. The last check we do is read the two instruction bytes at the faulting RIP. Since it points to a user mode page, we temporarily disable SMAP to read them from kernel mode, then re-enable it. We compare those bytes against 0F A2 (CPUID opcode) and if they don’t match, it’s not our exception again and we forward to the original handler.

If all these checks pass, it means that the faulting instruction is CPUID. We then call gp_handler to handle it.

```cpp,linenos
extern "C" void gp_handler( reg_context* context, UINT64 faulting_rip )
{
    UNREFERENCED_PARAMETER( faulting_rip );
    UINT32 leaf = ( UINT32 )context->rax;
    UINT32 subleaf = ( UINT32 )context->rcx;
    int regs[ 4 ]{};
    __cpuidex( regs, leaf, subleaf );
    switch ( leaf )
    {
    case 0:
    {
        regs[ 1 ] = 0x6B616552; // "Reak"
        regs[ 3 ] = 0x6B616552; // "Reak"
        regs[ 2 ] = 0x6B616552; // "Reak"
        break;
    }
    case 0x40000000:
    {
        regs[ 0 ] = 0x0;
        regs[ 1 ] = 0x76486F4E; // "NoHv"
        regs[ 2 ] = 0x76486F4E; // "NoHv"
        regs[ 3 ] = 0x76486F4E; // "NoHv"
        break;
    }
    default:
    {
        break;
    }
    }
    context->rax = ( UINT64 )regs[ 0 ];
    context->rbx = ( UINT64 )regs[ 1 ];
    context->rcx = ( UINT64 )regs[ 2 ];
    context->rdx = ( UINT64 )regs[ 3 ];
    // [original rsp + 8]
    UINT64* saved_rip = ( UINT64* )( ( UINT8* )context + sizeof( reg_context ) + 0x8 );
    *saved_rip += 2;
}
```

The handler receives the saved register context. It reads the CPUID leaf from rax and the subleaf from rcx, then executes __cpuidex to get the real results first. The switch statement then handles the specific leaves we want to intercept. Leaf 0 returns the CPU vendor string, which is normally “GenuineIntel”. Here we replace it with “ReakReakReak” as a demonstration that the interception works. Leaf 0x40000000 is the hypervisor leaf, which is empty if no hypervisor is running. We return “NoHvNoHvNoHv” instead of the real values. Any other leaf we don’t handle returns the real CPUID result unmodified. The next part of the handler is advancing the RIP. When a fault occurs, the CPU saves the RIP of the faulting instruction itself, not the next one. This means if we return without advancing it, the execution goes back to the same RIP, faults again, ending in an infinite loop. To fix this, we increment the saved RIP by 2, as we know it’s the size of the CPUID instruction (0F A2) so that when we return, execution resumes at the next instruction.

```asm,linenos
pop rax
pop rcx
pop rdx
pop rbx
pop rbp
pop rsi
pop rdi
pop r8
pop r9
pop r10
pop r11
pop r12
pop r13
pop r14
pop r15
swapgs ; swap back to usermode gs
add rsp, 8 ; remove error code from stack frame
iretq ; return from interrupt
```

Before returning, we restore the GPRs, call swapgs again to restore the user mode GS, then remove the error code from stack as iretq doesn’t expect it. Then, iretq restores RIP, CS, RFLAGS, RSP and SS from the stack frame and returns execution to user mode.

## Results

![intercepting_cpuid_without_a_hypervisor-4](/images/posts/intercepting_cpuid_without_a_hypervisor-4.png)

![intercepting_cpuid_without_a_hypervisor-5](/images/posts/intercepting_cpuid_without_a_hypervisor-5.png)

The hook is confirmed in WinDbg, with IDT[0xD] pointing to our stub. The console output shows our spoofed values, confirming that we can fully intercept CPUID calls made from user mode without a hypervisor.

## Behavior Under a Hypervisor

Now for another interesting part. One of the most fundamental behaviors of a VMX hypervisor is that CPUID causes a VM exit unconditionally. Or so the SDM says:

![intercepting_cpuid_without_a_hypervisor-6](/images/posts/intercepting_cpuid_without_a_hypervisor-6.png)

However, from my own testing, I found that this isn’t always the case:

When measuring the CPUID overhead on bare metal, it costs around 100 cycles. With my hypervisor running, it rises to ~1000 cycles. With both my hypervisor and CPUID faulting active, it doubles to ~2000 cycles. And with only CPUID faulting, it costs ~1000 cycles again. Interesting.

I spent some time trying to figure out why, and the reason is actually straightforward. Inside our gp_handler, we execute CPUID again to get the real values, but since we’re now at CPL 0, it triggers a VM exit instead of faulting again. So we end up handling #GP and VM back to back in one CPUID call from user mode, which explains the doubled cost.

But why? Shouldn’t CPUID trigger a VM exit unconditionally, as the SDM states? After digging through the SDM, I found a section that explains exactly why that’s not always the case:

![intercepting_cpuid_without_a_hypervisor-7](/images/posts/intercepting_cpuid_without_a_hypervisor-7.png)

CPUID VM exits are unconditional, unless a privilege level based #GP fires first. MSR_MISC_FEATURES_ENABLES (0x140) bit 0 does exactly that: it turns CPUID at CPL 3 into a privilege level fault, which according to this section takes priority over the VM exit. The VM exit never occurs, unless you call CPUID again from inside the handler. If you know what you want to return you can skip it entirely and avoid the VM exit.

## Practical Value

Practical use cases are limited. This technique is more interesting as a proof of concept than something that would be used for real purposes.

Hypothetically, you could use this method to tamper with user mode anti-tamper solutions that rely on CPUID as a part of their fingerprint on the hardware, without running a hypervisor. However in practice, the ~1000 cycle overhead is a dead giveaway to any timing aware anti-tamper solution.

If a hypervisor isn’t properly hardened and allows the guest to hook the #GP handler and allows write to MSR_MISC_FEATURES_ENABLES (0x140), the guest could cache all CPUID leaves, then intercept every user mode CPUID call and return either the cached values or intercepted ones without calling CPUID again, bypassing the hypervisor handling entirely. It could cause unexpected behavior in a hypervisor that relies on CPUID for feature detection for example.

Additionally, it could be used to trick programs that rely on specific CPU features to start to bypass those checks entirely.

## Conclusion

At the end of the day, this isn’t a groundbreaking find, as the MSR has already been documented, the quirks related to it have been discussed and worked on across some Linux kernel mailing list threads, and in reality, there are very few practical use cases for it. Yet, it remains obscure and unknown even to most people interested in hypervisors, and it’s exactly why I decided to write this post. All things considered, messing around with the OS and experimenting to see how the CPU behaves has been both fun and a great learning experience for me.
