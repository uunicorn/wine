/*
 * SetupAPI stubs
 *
 * Copyright 2000 James Hatheway
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdarg.h>

#include "wine/debug.h"
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winnls.h"
#include "winreg.h"
#include "setupapi.h"

WINE_DEFAULT_DEBUG_CHANNEL(setupapi);

/***********************************************************************
 *		TPWriteProfileString (SETUPX.62)
 */
BOOL WINAPI TPWriteProfileString16( LPCSTR section, LPCSTR entry, LPCSTR string )
{
    FIXME( "%s %s %s: stub\n", debugstr_a(section), debugstr_a(entry), debugstr_a(string) );
    return TRUE;
}


/***********************************************************************
 *		suErrorToIds  (SETUPX.61)
 */
DWORD WINAPI suErrorToIds16( WORD w1, WORD w2 )
{
    FIXME( "%x %x: stub\n", w1, w2 );
    return 0;
}

/***********************************************************************
 *		SetupDiOpenClassRegKeyExW  (SETUPAPI.@)
 *
 * WINAPI in description not given
 */
HKEY WINAPI SetupDiOpenClassRegKeyExW(LPGUID class, DWORD access, DWORD flags, LPCWSTR  machine, PVOID reserved)
{
  FIXME("\n");
  return INVALID_HANDLE_VALUE;
}

/***********************************************************************
 *		SetupDiGetClassDescriptionExW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiGetClassDescriptionExW (GUID* class, LPCWSTR desc, DWORD size, PDWORD required, LPCWSTR  machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiClassNameFromGuidExW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiClassNameFromGuidExW (GUID* class, LPCWSTR desc, DWORD size, PDWORD required, LPCWSTR  machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiBuildClassInfoListExW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiBuildClassInfoListExW(DWORD flags, LPGUID list, DWORD size, PDWORD required,  LPCWSTR  machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiGetDeviceInfoListDetailW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiGetDeviceInfoListDetailA(HDEVINFO devinfo, PSP_DEVINFO_DATA devinfo_data )
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiGetDeviceInfoListDetailW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiGetDeviceInfoListDetailW(HDEVINFO devinfo, PSP_DEVINFO_DATA devinfo_data )
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiCreateDeviceInfoListA (SETUPAPI.@)
 */
HDEVINFO WINAPI SetupDiCreateDeviceInfoList(LPGUID class, HWND parend)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiCreateDeviceInfoListExW  (SETUPAPI.@)
 */
HDEVINFO WINAPI SetupDiCreateDeviceInfoListExW(LPGUID class, HWND parend, LPCWSTR machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		  (SETUPAPI.@)
 *
 * NO WINAPI in description given
 */
HDEVINFO WINAPI SetupDiGetClassDevsExA(LPGUID class, LPCSTR filter, HWND parent, DWORD flags, HDEVINFO deviceset, LPCSTR machine, PVOID reserved)
{
  FIXME("filter %s machine %s\n",debugstr_a(filter),debugstr_a(machine));
  return FALSE;
}

/***********************************************************************
 *		  (SETUPAPI.@)
 *
 * NO WINAPI in description given
 */
HDEVINFO WINAPI SetupDiGetClassDevsExW(LPGUID class, LPCWSTR filter, HWND parent, DWORD flags, HDEVINFO deviceset, LPCWSTR machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		SetupDiClassGuidsFromNameExW  (SETUPAPI.@)
 */
BOOL WINAPI SetupDiClassGuidsFromNameExW(LPCWSTR class, LPGUID list, DWORD size, PDWORD required,  LPCWSTR  machine, PVOID reserved)
{
  FIXME("\n");
  return FALSE;
}

/***********************************************************************
 *		CM_Connect_MachineW  (SETUPAPI.@)
 */
DWORD WINAPI CM_Connect_MachineW(LPCWSTR name, void * machine)
{
#define  CR_SUCCESS       0x00000000
#define  CR_ACCESS_DENIED 0x00000033
  FIXME("\n");
  return  CR_ACCESS_DENIED;
}

/***********************************************************************
 *		CM_Disconnect_Machine  (SETUPAPI.@)
 */
DWORD WINAPI CM_Disconnect_Machine(DWORD handle)
{
  FIXME("\n");
  return  CR_SUCCESS;

}

/***********************************************************************
 *		SetupCopyOEMInfA  (SETUPAPI.@)
 */
BOOL WINAPI SetupCopyOEMInfA(LPCSTR sourceinffile, LPCSTR sourcemedialoc,
			    DWORD mediatype, DWORD copystyle, LPSTR destinfname,
			    DWORD destnamesize, PDWORD required,
			    LPSTR destinfnamecomponent)
{
  FIXME("stub: source %s location %s ...\n",sourceinffile, sourcemedialoc);
  return FALSE;
}

/***********************************************************************
 *		InstallHinfSection  (SETUPAPI.@)
 */
void WINAPI InstallHinfSection(HWND hwnd, HINSTANCE handle, LPCSTR cmdline, INT show)
{
    FIXME("stub, hwnd %p, handle %p, cmdline %s\n", hwnd, handle, debugstr_a(cmdline));
}
