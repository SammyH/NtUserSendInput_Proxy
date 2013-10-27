/*
    Proof of concept

    Windows XP driver for bypassing SSDT hooks by copying the shadow table when the driver is loaded and
        allowing the functions to be called indirectly through DeviceIoControl

    Sammy Hosny
*/

#include <ntddk.h>

#define		NTUSI_PROXY_DEV_LINK	L"\\DosDevices\\NtUserSendInput_Proxy"
#define		NTUSI_PROXY_DEV_NAME	L"\\Device\\NtUserSendInput_Proxy"

#define		FILE_DEVICE_NT_PROXY		 0x00008812
#define		IOCTL_SEND_INPUT          		(ULONG) CTL_CODE(FILE_DEVICE_NT_PROXY, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define		IOCTL_VALIDATE          		(ULONG) CTL_CODE(FILE_DEVICE_NT_PROXY, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS ZwQuerySystemInformation( 
		IN ULONG SystemInformationClass, 
		IN PVOID SystemInformation, 
		IN ULONG SystemInformationLength, 
		OUT PULONG ReturnLength);

NTSTATUS ZwDuplicateObject(
                 IN HANDLE                 SourceProcessHandle,
                 IN PHANDLE                 SourceHandle,
                 IN HANDLE                 TargetProcessHandle,
                 OUT PHANDLE               TargetHandle,
                 IN ACCESS_MASK             DesiredAccess OPTIONAL,
                 IN BOOLEAN                 InheritHandle,
                 IN ULONG                   Options );

NTSTATUS ZwQueryObject(
				IN HANDLE                ObjectHandle,
				IN ULONG                 ObjectInformationClass,
				OUT PVOID                ObjectInformation,
				IN ULONG                 ObjectInformationLength,
				OUT PULONG               ReturnLength OPTIONAL);


NTSTATUS PsLookupProcessByProcessId(
	   IN ULONG               ulProcId, 
	   OUT PEPROCESS *        pEProcess);
	   
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef void* PVOID;
typedef unsigned short WORD;
	   
typedef struct _KAPC_STATE 
{ 
   LIST_ENTRY ApcListHead[2]; 
   PVOID Process; 
   BOOLEAN KernelApcInProgress; 
   BOOLEAN KernelApcPending; 
   BOOLEAN UserApcPending; 
} KAPC_STATE, *PKAPC_STATE; 
 
 
typedef struct tagMOUSEINPUT { 
    LONG dx; 
    LONG dy; 
    DWORD mouseData; 
    DWORD dwFlags; 
    DWORD time; 
    ULONG_PTR dwExtraInfo; 
} MOUSEINPUT, *PMOUSEINPUT; 
 
typedef struct tagKEYBDINPUT { 
    WORD wVk; 
    WORD wScan; 
    DWORD dwFlags; 
    DWORD time; 
    ULONG_PTR dwExtraInfo; 
} KEYBDINPUT, *PKEYBDINPUT; 

typedef struct tagINPUT {  
DWORD type;  
union {MOUSEINPUT mi;  
		KEYBDINPUT ki; 
		//HARDWAREINPUT hi; 
	   }; 
}INPUT, *PINPUT; 

typedef UINT (__stdcall*NTUSERSENDINPUT)( 
   UINT cInputs, 
   PINPUT pInputs, 
   int cbSize 
); 

VOID KeStackAttachProcess(
  __inout  PRKPROCESS Process,
  __out    PKAPC_STATE ApcState
);
VOID KeUnstackDetachProcess(
  __in  PKAPC_STATE ApcState
);


NTUSERSENDINPUT g_oNtUserSendInput;

#define ObjectNameInformation  1

#define SystemHandleInformation 0x10

#pragma pack(1)
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} _SYSTEM_HANDLE_INFORMATION, *P_SYSTEM_HANDLE_INFORMATION;


typedef struct _SYSTEM_HANDLE_INformATION_EX {
	ULONG NumberOfHandles;
	_SYSTEM_HANDLE_INFORMATION Information[1];
} _SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct ServiceDescriptorEntry {
	PVOID *ServiceTableBase;
	ULONG *ServiceCounterTableBase; //Used only in checked build
	ULONG NumberOfServices;
	PVOID *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry KeServiceDescriptorTable;
__declspec(dllimport) _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);

PServiceDescriptorTableEntry KeServiceDescriptorTableShadow;

ULONG NtUserSendInputIndex = 0x1F6;

unsigned int getAddressOfShadowTable()
{
    unsigned int i;
    unsigned char *p;
    unsigned int dwordatbyte;

    p = (unsigned char*) KeAddSystemServiceTable;

    for(i = 0; i < 4096; i++, p++)
    {
        __try
        {
            dwordatbyte = *(unsigned int*)p;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }

        if(MmIsAddressValid((PVOID)dwordatbyte))
        {
            if(memcmp((PVOID)dwordatbyte, &KeServiceDescriptorTable, 16) == 0)
            {
                if((PVOID)dwordatbyte == &KeServiceDescriptorTable)
                {
                    continue;
                }

                return dwordatbyte;
            }
        }
    }

    return 0;
}

ULONG getShadowTable()
{
    KeServiceDescriptorTableShadow = (PServiceDescriptorTableEntry) getAddressOfShadowTable();

    if(KeServiceDescriptorTableShadow == NULL)
    {
        DbgPrint("Couldn't find KeServiceDescriptorTableShadow!");
        
        return FALSE;
    }
    else
    {
        DbgPrint("KeServiceDescriptorTableShadow found @ 0x%p!\n", KeServiceDescriptorTableShadow);
        DbgPrint("KeServiceDescriptorTableShadow entries: %d\n", KeServiceDescriptorTableShadow[1].NumberOfServices);
        return TRUE;
    }
}

PVOID GetInfoTable(ULONG ATableType)
{
  ULONG mSize = 0x4000;
  PVOID mPtr = NULL;
  NTSTATUS St;
  do
  {
     mPtr = ExAllocatePool(PagedPool, mSize);
     memset(mPtr, 0, mSize);
     if (mPtr)
     {
        St = ZwQuerySystemInformation(ATableType, mPtr, mSize, NULL);
     } else return NULL;
     if (St == STATUS_INFO_LENGTH_MISMATCH)
     {
        ExFreePool(mPtr);
        mSize = mSize * 2;
     }
  } while (St == STATUS_INFO_LENGTH_MISMATCH);
  if (St == STATUS_SUCCESS) return mPtr;
  ExFreePool(mPtr);
  return NULL;
}

HANDLE GetCsrPid()
{
	HANDLE Process, hObject;
	HANDLE CsrId = (HANDLE)0;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID cid;
	UCHAR Buff[0x100];
	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;
	PSYSTEM_HANDLE_INFORMATION_EX Handles;
	ULONG r;

	Handles = GetInfoTable(SystemHandleInformation);

	if (!Handles) return CsrId;

	for (r = 0; r < Handles->NumberOfHandles; r++)
	{
		if (Handles->Information[r].ObjectTypeNumber == 21) //Port object
		{
			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			cid.UniqueProcess = (HANDLE)Handles->Information[r].ProcessId;
			cid.UniqueThread = 0;

			if (NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
			{
				if (NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[r].Handle,NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
				{
					if (NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
					{
						if (ObjName->Name.Buffer && !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
						{
						  CsrId = (HANDLE)Handles->Information[r].ProcessId;
						} 
					}

					ZwClose(hObject);
				}

				ZwClose(Process);
			}
		}
	}

	ExFreePool(Handles);
	return CsrId;
}
BOOLEAN Sleep(ULONG MillionSecond)   
{   
     NTSTATUS ntStatus;   
     LARGE_INTEGER DelayTime;   
     DelayTime = RtlConvertLongToLargeInteger(-10000*MillionSecond);   
     ntStatus = KeDelayExecutionThread( KernelMode, FALSE, &DelayTime );   
     if( NT_SUCCESS(ntStatus) )   
          return TRUE;   
     else   
          return FALSE;   
}

NTSTATUS Drv_Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("Drv_Create\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}

NTSTATUS Drv_Close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("Drv_Close\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}

NTSTATUS DrvIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION IrpSp;
	
	DbgPrint("DrvIoctlDispatch called\n");
	
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	
	switch(IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_SEND_INPUT:
		{
			typedef struct _SendInputParams {
				UINT numInputs;
				PINPUT pInputs;
				int cbSize;
			} SendInputParams;
			if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(SendInputParams)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT))
			{
				Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
				Irp->IoStatus.Information = 0L;
			} else {
				SendInputParams Params;// = (SendInputParams*)Irp->AssociatedIrp.SystemBuffer;
				UINT ret = 0;
				RtlCopyMemory(&Params, Irp->AssociatedIrp.SystemBuffer, sizeof(SendInputParams));
				
				DbgPrint("Params.pInputs = 0x%p\n", Params.pInputs);
				DbgPrint("Params.pInputs->type = %d\n", Params.pInputs->type);
				ret = g_oNtUserSendInput(Params.numInputs, Params.pInputs, Params.cbSize);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &ret, sizeof(UINT));
				
				DbgPrint("IOCTL_SEND_INPUT triggered. numInputs = %d; ret = %d\n", Params.numInputs, ret);
				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof(UINT);
			}
		} break;
		case IOCTL_VALIDATE:
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0L;
			/*UCHAR outBuffer[32+8];
			int i = 0;
			DbgPrint("IOCTL_VALIDATE triggered.\n");
			*(DWORD*)(&outBuffer[0]) = 1337;
			*(DWORD*)(&outBuffer[4]) = 1337*2;
			RtlCopyMemory(&outBuffer[8], g_oNtUserSendInput, 32);
			
			for(i = 0; i < 32; i++)
				DbgPrint("[0x%02X]", outBuffer[i+8]);
			DbgPrint("\n");
			if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < 32+8)
			{
				Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
				Irp->IoStatus.Information = 0L;
				DbgPrint("IOCTL_VALIDATE: Buffer too small (%d<32+8).\n", IrpSp->Parameters.DeviceIoControl.OutputBufferLength);
			} else {
				*(DWORD*)(&outBuffer[0]) = (DWORD)g_oNtUserSendInput;
				if(outBuffer[8]==0xE9)
				{
					DWORD offset = *(DWORD*)(&outBuffer[9]);
					DWORD addr = ((DWORD)g_oNtUserSendInput+5)+offset;
					*(DWORD*)(&outBuffer[4]) = (DWORD)addr;
				}
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, outBuffer, sizeof(UCHAR)*32);
				DbgPrint("Copied outBuffer successfully\n");
				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof(UCHAR)*32;
			}*/
		}
	}
	
	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, 0);
	return status;
}

NTSTATUS DrvDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION IrpSp;
	
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	
	switch(IrpSp->MajorFunction)
	{
		case IRP_MJ_CREATE:
		{
			DbgPrint("DrvDispatch IRP_MJ_CREATE\n");
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0L;
		} break;
		
		case IRP_MJ_CLOSE:
		{
			DbgPrint("DrvDispatch IRP_MJ_CLOSE\n");
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0L;
		} break;
		
		default:
		{
			DbgPrint("[DrvDispatch] Unknown MajorFunction request %d\n", IrpSp->MajorFunction);
		} break;
	}
	
	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, 0);
	return status;
}

PEPROCESS crsEProc;
PMDL g_pMdlSystemCall = 0;
PVOID* MappedSystemCallTable;

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING linkString;
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("Device deleted.\n");
	RtlInitUnicodeString(&linkString, NTUSI_PROXY_DEV_LINK);
	IoDeleteSymbolicLink(&linkString);
	DbgPrint("Symbolic link deleted.\n");

	if(MappedSystemCallTable)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pMdlSystemCall);
		IoFreeMdl(g_pMdlSystemCall);
		DbgPrint("System call table free'd\n");
	}

	DbgPrint("Driver unloaded\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PKAPC_STATE ApcState;
	UNICODE_STRING nameString, linkString;
	PDEVICE_OBJECT deviceObject;

	DbgPrint("Hello, World!\n");
	
	getShadowTable();
	
	status = PsLookupProcessByProcessId((ULONG)GetCsrPid(), &crsEProc);
	if (!NT_SUCCESS( status ))
	{
		DbgPrint("PsLookupProcessByProcessId() error\n");
		return status;
	}
	ApcState = (PKAPC_STATE)ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));
	KeStackAttachProcess(crsEProc, ApcState);
	
	g_pMdlSystemCall = IoAllocateMdl(
		KeServiceDescriptorTableShadow[1].ServiceTableBase,
		KeServiceDescriptorTableShadow[1].NumberOfServices*4,
		FALSE, //not associated with an IRP
		FALSE, //charge quota, should be FALSE
		NULL); //IRP* should be NULL
	if(!g_pMdlSystemCall)
		return STATUS_UNSUCCESSFUL;
	
	MmBuildMdlForNonPagedPool(g_pMdlSystemCall);
	g_pMdlSystemCall->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
	MappedSystemCallTable = MmMapLockedPages(g_pMdlSystemCall, KernelMode);
	
	try
	{
		if(KeServiceDescriptorTableShadow != NULL)
		{
			g_oNtUserSendInput = (NTUSERSENDINPUT)MappedSystemCallTable[NtUserSendInputIndex];
			if(*(UCHAR*)(g_oNtUserSendInput)==0xE9)
			{
				DWORD offset = *(DWORD*)((DWORD)g_oNtUserSendInput+1);
				DWORD addr = ((DWORD)g_oNtUserSendInput+5)+offset;
				g_oNtUserSendInput = (DWORD)addr;
			}
			DbgPrint("g_oNtUserSendInput = 0x%p\n", g_oNtUserSendInput);
		}
	}
	finally
	{
		KeUnstackDetachProcess(ApcState);
	}
	
	DbgPrint("Creating device..\n");
	
	
	RtlInitUnicodeString(&nameString, NTUSI_PROXY_DEV_NAME);
	status = IoCreateDevice( DriverObject,
							0,
							&nameString,
							FILE_DEVICE_UNKNOWN,
							0,
							TRUE, //exclusive
							&deviceObject);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice failed. status = %d\n", status);
		return status;
	}
	
	RtlInitUnicodeString(&linkString, NTUSI_PROXY_DEV_LINK);
	status = IoCreateSymbolicLink(&linkString, &nameString);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateSymbolicLink failed. status = %d\n", status);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatch;
	
	DriverObject->DriverUnload = DriverUnload;
	DbgPrint("Device created & IRP handler assigned.\n");
	
	//DbgPrint("SendInput [0x11F6] 0x%p\n", KeServiceDescriptorTable[1].ServiceTableBase[0x1F6]);
	//DbgPrint("Number of services in GDI system call table [0x%p]: %u\n", &KeServiceDescriptorTableShadow[1], (ULONG)KeServiceDescriptorTableShadow[1].NumberOfServices);
	return STATUS_SUCCESS;
}