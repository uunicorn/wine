
#define WINBOOL BOOL
#include "winusb.h"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "wine/debug.h"

#undef _WIN32
#undef _WIN64
#undef _MSC_VER
#undef interface
#include <libusb.h>

#define MAX_DEVICES 100

WINE_DEFAULT_DEBUG_CHANNEL(winusb);

struct driver_info {
    libusb_context *ctx;
    struct {
        long vend_id;
        long prod_id;
    } supported_devices[100];
    int supported_devices_cnt;
    struct libusb_device_descriptor descr;
    libusb_device_handle * dev;

    DWORD timeouts[0x100];
    volatile char abort[0x100];

    FILE *script;
    int playback;
    int script_line;
};

WINUSB_PIPE_INFORMATION info[] = {
    { UsbdPipeTypeBulk, 0x01, 0x40, 0 },
    { UsbdPipeTypeBulk, 0x81, 0x40, 0 },
    { UsbdPipeTypeBulk, 0x82, 0x40, 0 },
    { UsbdPipeTypeInterrupt, 0x83, 0x08, 4 },
    { UsbdPipeTypeInterrupt, 0x84, 0x10, 10 },
};

#define xstr(a) str(a)
#define str(a) #a
#define err(x) res_err(x, xstr(x))

void res_err(int result, const char* where) {
    if (result != 0) {
        ERR("Failed '%s': %d - %s\n", where, result, libusb_error_name(result));
        exit(0);
    }
}


WINBOOL WINAPI 
WinUsb_GetDescriptor(
            WINUSB_INTERFACE_HANDLE InterfaceHandle, 
            UCHAR DescriptorType, 
            UCHAR Index,
            USHORT LanguageID,
            PUCHAR Buffer,
            ULONG BufferLength,
            PULONG LengthTransferred)
{
    struct driver_info *info = InterfaceHandle;
    int rc, i;
    uint16_t dti = (uint16_t)((DescriptorType << 8) | Index);

    TRACE("\n");

    if(!info->playback) {
        rc = libusb_control_transfer(info->dev, LIBUSB_ENDPOINT_IN,
                    LIBUSB_REQUEST_GET_DESCRIPTOR, dti,
                    LanguageID, Buffer, (uint16_t) BufferLength, 1000);


        if(rc >= 0) {
            fprintf(info->script, "blackbox: usb %d dsc ", dti);
            for(i=0;i<rc;i++) {
                fprintf(info->script, "%02x", Buffer[i]);
            }
            fprintf(info->script, "\r\n");
            fflush(info->script);
        }
    }
    else {
        int p;
        char dir[10];
        char hex[8000000], *hp;

        info->script_line++;
        fscanf(info->script, "blackbox: usb %d %s %s\n", &p, dir, hex);
        
        if(p != dti) {
            ERR("wrong dtype or index on script line %d (expected %d, requested %d)\n", info->script_line, p, dti);
            exit(0);
        }
        if(strcmp(dir, "dsc") != 0) {
            ERR("wrong direction on script line %d (expected %s, requested %s)\n", info->script_line, dir, "dsc");
            exit(0);
        }
        rc=0;
        for(hp=hex;*hp;hp+=2) {
            char hh[] = { hp[0], hp[1], 0 }, *hhp;
            int b = strtol(hh, &hhp, 0x10);

            if(hhp - hh != 2) {
                ERR("broken hex value on script line %d: %s\n", info->script_line, hp);
                exit(0);
            }
            Buffer[rc] = b;
            rc++;
        }
    }

    TRACE("rc=%d\n", rc);
    *LengthTransferred = rc;

    if(rc < 0)
        return FALSE;

    return TRUE;
}

WINBOOL WINAPI 
WinUsb_QueryInterfaceSettings(
            WINUSB_INTERFACE_HANDLE InterfaceHandle, 
            UCHAR AlternateInterfaceNumber, 
            PUSB_INTERFACE_DESCRIPTOR UsbAltInterfaceDescriptor)
{
    TRACE("\n");
    return FALSE;
}

WINBOOL WINAPI 
WinUsb_ControlTransfer(
            WINUSB_INTERFACE_HANDLE InterfaceHandle, 
            WINUSB_SETUP_PACKET SetupPacket,
            PUCHAR Buffer,
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    struct driver_info *info = InterfaceHandle;
    int rc, i;

    TRACE("%x %x %x %x %x\n", 
                SetupPacket.RequestType, 
                SetupPacket.Request, 
                SetupPacket.Value, 
                SetupPacket.Index,
                SetupPacket.Length);
#if 0
    printf("Before: ");
    for(i=0;i<BufferLength;i++) {
        if(i > 80000) {
            printf("...");
            break;
        } else {
            printf("%02x", Buffer[i]);
        }
    }
    printf("\r\n");
#endif
    if(!info->playback) {
        rc = libusb_control_transfer(info->dev,
            SetupPacket.RequestType, SetupPacket.Request, SetupPacket.Value, SetupPacket.Index,
            Buffer, SetupPacket.Length, 10000);
    }
    else {
        rc = SetupPacket.Length;
    }
    TRACE("rc=%d\n", rc);
    
    if(rc < 0) 
        return FALSE;
#if 0 
    printf("After: ");
    for(i=0;i<BufferLength;i++)
        printf("%02x ", Buffer[i]);
    printf("\r\n");
#endif

    *LengthTransferred = rc;
    return TRUE;
}

WINBOOL WINAPI 
WinUsb_ReadPipe(
            WINUSB_INTERFACE_HANDLE InterfaceHandle, 
            UCHAR PipeID, 
            PUCHAR Buffer, 
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    struct driver_info *dev = InterfaceHandle;
    WINUSB_PIPE_INFORMATION *wpi = NULL;
    int i, rc;


    TRACE("PipeID=%d\n", PipeID);

    for(i=0;i<sizeof(info)/sizeof(*info);i++) {
        if(info[i].PipeId == PipeID)
            wpi = info + i;
    }
    if(!wpi) {
        ERR("unknown pipe!\n");
        return FALSE;
    }
    if(!dev->playback) {
        switch(wpi->PipeType) {
            case UsbdPipeTypeBulk:
                TRACE("bulk xfer\n");
                rc = libusb_bulk_transfer(
                        dev->dev, 
                        PipeID, 
                        Buffer, 
                        BufferLength, 
                        (int*)LengthTransferred, 
                        dev->timeouts[PipeID]+1000);
                //sleep(3);
                break;

            case UsbdPipeTypeInterrupt:
                TRACE("interrupt xfer?\n");
                dev->abort[PipeID] = 1;
                for(i=0;;) {
                    rc = libusb_interrupt_transfer(
                            dev->dev, 
                            PipeID, 
                            Buffer, 
                            BufferLength, 
                            (int*)LengthTransferred, 
                            200);
                    
                    TRACE("libusb_interrupt_transfer=%d!\n", rc);

                    if(rc == LIBUSB_ERROR_TIMEOUT) {
                        if(dev->abort[PipeID] == 2) {
                            WARN("Pipe was aborted!\n");
                            rc = 0;
                            break;
                        }

                        if(dev->timeouts[PipeID]) {
                            if(i > dev->timeouts[PipeID])
                                break;
                            else
                                i += 200;
                        }
                        continue;
                    }

                    break;
                }
                dev->abort[PipeID] = 0;
                break;

            default:
                ERR("unknown pipe type!\n");
                return FALSE;
        }

        if(rc < 0)  {
            ERR("xfer Failed - %s\n", libusb_error_name(rc));
            exit(0);
            return FALSE;
        }

        fprintf(dev->script, "blackbox: usb %d <<< ", PipeID);
        for(i=0;i<*LengthTransferred;i++) {
            if(i > 8000000) {
                fprintf(dev->script, "....");
                break;
            } else {
                fprintf(dev->script, "%02x", Buffer[i]);
            }
        }
        fprintf(dev->script, "\r\n");
        fflush(dev->script);

    }
    else {
        int p;
        char dir[10];
        char hex[8000000], *hp;

        dev->script_line++;
        fscanf(dev->script, "blackbox: usb %d %s %s\n", &p, dir, hex);
        if(p != PipeID) {
            ERR("wrong pipe on script line %d (expected %d, requested %d)\n", dev->script_line, p, PipeID);
            exit(0);
        }
        if(strcmp(dir, "<<<") != 0) {
            ERR("wrong direction on script line %d (expected %s, requested %s)\n", dev->script_line, dir, "<<<");
            exit(0);
        }
        *LengthTransferred=0;
        for(hp=hex;*hp;hp+=2) {
            char hh[] = { hp[0], hp[1], 0 }, *hhp;
            int b = strtol(hh, &hhp, 0x10);

            if(hhp - hh != 2) {
                ERR("broken hex value on script line %d: %s\n", dev->script_line, hp);
                exit(0);
            }
            Buffer[*LengthTransferred] = b;
            (*LengthTransferred)++;
        }

    }


    return TRUE;
}

WINBOOL
claim_device(struct driver_info *info)
{
    libusb_device ** dev_list;
    int i, j;
    int dev_cnt = libusb_get_device_list(info->ctx, &dev_list);

    for (i = 0; i < dev_cnt; i++) {
        struct libusb_device_descriptor descriptor;

        libusb_get_device_descriptor(dev_list[i], &descriptor);

        for(j = 0;j < info->supported_devices_cnt;j++) {
            if (info->supported_devices[j].vend_id == descriptor.idVendor && 
                    info->supported_devices[j].prod_id == descriptor.idProduct) {
                TRACE("Found device %04x:%04x\n", descriptor.idVendor, descriptor.idProduct);

                err(libusb_get_device_descriptor(dev_list[i], &info->descr));
                err(libusb_open(dev_list[i], &info->dev));
                err(libusb_reset_device(info->dev));
                err(libusb_set_configuration(info->dev, 1));
                err(libusb_claim_interface(info->dev, 0));

                return TRUE;
            }
        }
    }

    ERR("!!!!!!!!!!!! No matching devices found\n");
    return FALSE;
}

WINBOOL WINAPI 
WinUsb_WritePipe(
            WINUSB_INTERFACE_HANDLE InterfaceHandle, 
            UCHAR PipeID,
            PUCHAR Buffer,
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    int i, rc;
    struct driver_info *dev = InterfaceHandle;
    int send;


    TRACE("PipeID=%x\n", PipeID);
    

    if(!dev->playback) {
        fprintf(dev->script, "blackbox: usb %d >>> ", PipeID);
        for(i=0;i<BufferLength;i++) {
            if(i > 8000000) {
                fprintf(dev->script, "...");
                break;
            } else {
                fprintf(dev->script, "%02x", Buffer[i]);
            }
        }
        fprintf(dev->script, "\r\n");
        fflush(dev->script);

        if(Buffer[0] == 0x10 && Buffer[1] == 0 && Buffer[2] == 0) {
            abort();
            return FALSE;
        }

        rc = libusb_bulk_transfer(dev->dev,
                PipeID,
                Buffer,
                BufferLength, 
                &send, 
                dev->timeouts[PipeID]+1000);
        TRACE("rc=%d send=%d\n", rc, send);

        if(rc < 0) {
            ERR("xfer Failed - %s\n", libusb_error_name(rc));
            exit(0);
            return FALSE;
        }
    }
    else {
        int p;
        char dir[10];
        char hex[8000000], *hp;

        dev->script_line++;
        fscanf(dev->script, "blackbox: usb %d %s %s\n", &p, dir, hex);
        if(p != PipeID) {
            ERR("wrong pipe on script line %d (expected %d, requested %d)\n", dev->script_line, p, PipeID);
            exit(0);
        }
        if(strcmp(dir, ">>>") != 0) {
            ERR("wrong direction on script line %d (expected %s, requested %s)\n", dev->script_line, dir, ">>>");
            exit(0);
        }
        send=0;
        for(hp=hex;*hp;hp+=2) {
            char hh[] = { hp[0], hp[1], 0 }, *hhp;
            int b = strtol(hh, &hhp, 0x10);

            if(hhp - hh != 2) {
                ERR("broken hex value on script line %d: %s\n", dev->script_line, hp);
                exit(0);
            }

            if(Buffer[send] != b) {
                ERR("send byte mismatch onscript line %d, column %ld: %02x != %02x\n", dev->script_line, hp-hex, b, Buffer[send]);
                exit(0);
            }
            send++;
        }
        if(send != BufferLength) {
            ERR("send != BufferLength on script line %d\n", dev->script_line);
            exit(0);
        }
    }
    *LengthTransferred = send;

    return TRUE;
}

WINBOOL WINAPI 
WinUsb_QueryPipe(
            WINUSB_INTERFACE_HANDLE InterfaceHandle,
            UCHAR AlternateInterfaceNumber,
            UCHAR PipeIndex,
            PWINUSB_PIPE_INFORMATION PipeInformation)
{
    TRACE("alt-if=%d pipe=%d\n", AlternateInterfaceNumber, PipeIndex);

    *PipeInformation = info[PipeIndex];

    return TRUE;
}

WINBOOL WINAPI WinUsb_ResetPipe (WINUSB_INTERFACE_HANDLE InterfaceHandle, UCHAR PipeID)
{
    TRACE("pipe=%d\n", PipeID);
    return TRUE;
}

// ============================================================

WINBOOL WINAPI 
WinUsb_SetPipePolicy(
            WINUSB_INTERFACE_HANDLE InterfaceHandle,
            UCHAR PipeID,
            ULONG PolicyType,
            ULONG ValueLength,
            PVOID Value)
{
    struct driver_info *info = InterfaceHandle;

    TRACE("pipe=%d, policy type=%d, val length=%d, val=%x\n", PipeID, PolicyType, ValueLength, *(DWORD*)Value);

    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        info->timeouts[PipeID] = *(DWORD*)Value;
    }
    return TRUE;
}

WINBOOL WINAPI WinUsb_FlushPipe (WINUSB_INTERFACE_HANDLE InterfaceHandle, UCHAR PipeID)
{
    TRACE("\n");
    return TRUE;
}

WINBOOL WINAPI WinUsb_AbortPipe (WINUSB_INTERFACE_HANDLE InterfaceHandle, UCHAR PipeID)
{
    struct driver_info *dev = InterfaceHandle;
    TRACE("%x\n", PipeID);
    if(dev->abort[PipeID] == 1) {
        dev->abort[PipeID] = 2;

        while(dev->abort[PipeID] != 0)
            usleep(200);
    }
    TRACE("abort complete\n");
    return TRUE;
}

WINBOOL WINAPI WinUsb_Free (WINUSB_INTERFACE_HANDLE InterfaceHandle)
{
    TRACE("\n");
    return TRUE;
}

WINBOOL WINAPI WinUsb_GetAssociatedInterface (WINUSB_INTERFACE_HANDLE InterfaceHandle, UCHAR AssociatedInterfaceIndex, PWINUSB_INTERFACE_HANDLE AssociatedInterfaceHandle)
{
    TRACE("\n");
    return FALSE;
}

WINBOOL WINAPI WinUsb_GetCurrentAlternateSetting (WINUSB_INTERFACE_HANDLE InterfaceHandle, PUCHAR SettingNumber)
{
    TRACE("\n");
    return FALSE;
}

WINBOOL WINAPI 
WinUsb_SetPowerPolicy(
            WINUSB_INTERFACE_HANDLE InterfaceHandle,
            ULONG PolicyType,
            ULONG ValueLength,
            PVOID Value)
{
    TRACE("\n");
    return TRUE;
}

WINBOOL WINAPI 
WinUsb_SetCurrentAlternateSetting(
            WINUSB_INTERFACE_HANDLE InterfaceHandle,
            UCHAR SettingNumber)
{
    TRACE("\n");
    return FALSE;
}

PUSB_INTERFACE_DESCRIPTOR WINAPI 
WinUsb_ParseConfigurationDescriptor (
            PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
            PVOID StartPosition,
            LONG InterfaceNumber,
            LONG AlternateSetting,
            LONG InterfaceClass,
            LONG InterfaceSubClass,
            LONG InterfaceProtocol)
{
    TRACE("\n");
    return NULL;
}

PUSB_COMMON_DESCRIPTOR WINAPI 
WinUsb_ParseDescriptors (PVOID DescriptorBuffer, 
            ULONG TotalLength,
            PVOID StartPosition,
            LONG DescriptorType)
{
    TRACE("\n");
    return NULL;
}

WINBOOL WINAPI WinUsb_GetPowerPolicy (WINUSB_INTERFACE_HANDLE InterfaceHandle, ULONG PolicyType, PULONG ValueLength, PVOID Value)
{
    TRACE("\n");
    return FALSE;
}


BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD     fdwReason, LPVOID    lpvReserved)
{
    TRACE("reason=%x\n", fdwReason);

    return TRUE;
}

WINBOOL WINAPI WinUsb_Initialize (HANDLE DeviceHandle, PWINUSB_INTERFACE_HANDLE InterfaceHandle)
{
    struct driver_info *info = malloc(sizeof(struct driver_info));
    const char *usbscript = getenv("USB_SCRIPT");
    const char *playback = getenv("USB_PLAYBACK");
    char buf[10*1024];
    char *saveptr, *line;
    DWORD sz;
    OVERLAPPED o = { 0 };

    memset(info, 0, sizeof(*info));

    *InterfaceHandle = info;
 
    TRACE("%p", DeviceHandle);
    if(DeviceHandle == INVALID_HANDLE_VALUE) {
        ERR("DeviceHandle == INVALID_HANDLE_VALUE\n");
        return FALSE;
    }

    o.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    if(!ReadFile(DeviceHandle, buf, sizeof(buf)-1, &sz, &o) && GetLastError() != ERROR_IO_PENDING) {
        ERR("ReadFile failed: %d\n", GetLastError());
        return FALSE;
    }

    if(!GetOverlappedResult(DeviceHandle, &o, &sz, TRUE)) {
        ERR("GetOverlappedResult failed: %d\n", GetLastError());
        return FALSE;
    }

    CloseHandle(o.hEvent);
    CloseHandle(DeviceHandle);

    buf[sz] = 0;
    line = strtok_r(buf, "\r\n", &line);

    for(info->supported_devices_cnt = 0, line = strtok_r(buf, "\r\n", &saveptr);
            info->supported_devices_cnt < MAX_DEVICES && line;
            info->supported_devices_cnt++, line = strtok_r(NULL, "\r\n", &saveptr)) {
        long vend_id, prod_id;
        char *colon;

        if(!*line)
            continue;

        colon = strchr(line, ':');
        
        if(colon == NULL) {
            ERR("missing ':' in usb.txt\n");
            return FALSE;
        }

        *colon = 0;
        vend_id = strtol(line, NULL, 16);
        prod_id = strtol(colon+1, NULL, 16);
        
        info->supported_devices[info->supported_devices_cnt].vend_id = vend_id;
        info->supported_devices[info->supported_devices_cnt].prod_id = prod_id; 

        TRACE("usb.txt: %04lx:%04lx\n", vend_id, prod_id);
    }

    if(info->supported_devices_cnt == 0) {
        ERR("usb.txt should have at least one line like <vendor>:<product>\n");
        return FALSE;
    }

    
    if(!usbscript || !*usbscript) {
        ERR("USB_SCRIPT was not set\n");
        return FALSE;
    }

    if(playback && *playback) {
        info->script = fopen(usbscript, "rt");
        info->playback = 1;
        if(info->script == NULL) {
            ERR("failed to open the USB script %s\r", usbscript);
            return FALSE;
        }

        info->script_line = 0;
        return TRUE;

    }
    else {
        info->script = fopen(usbscript, "wt");
        info->playback = 0;

        info->dev = NULL;
        libusb_init(&info->ctx);
        //libusb_set_debug(info->ctx, 3);

        return claim_device(info);
    }
}

WINBOOL WINAPI WinUsb_GetOverlappedResult (WINUSB_INTERFACE_HANDLE InterfaceHandle, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, WINBOOL bWait)
{
    TRACE("\r");
    return FALSE;
}

WINBOOL WINAPI 
WinUsb_GetPipePolicy(
            WINUSB_INTERFACE_HANDLE InterfaceHandle,
            UCHAR PipeID,
            ULONG PolicyType,
            PULONG ValueLength,
            PVOID Value)
{
    struct driver_info *info = InterfaceHandle;

    TRACE("PipeID=%d PolicyType=%d ValueLength=%d\n", 
                PipeID, 
                PolicyType,
                *ValueLength);
    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        *(DWORD*)Value = info->timeouts[PipeID];
    }
    TRACE("PipeID=%d PolicyType=%d ValueLength=%d Value=%x\n", 
                PipeID, 
                PolicyType,
                *ValueLength,
                *(DWORD*)Value);
    return TRUE;
}

WINBOOL WINAPI 
WinUsb_QueryDeviceInformation(
        WINUSB_INTERFACE_HANDLE InterfaceHandle,
        ULONG InformationType, 
        PULONG BufferLength, 
        PVOID Buffer)
{
    TRACE("\n");
    return FALSE;
}

