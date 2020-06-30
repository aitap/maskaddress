#include <assert.h>
#include <stdio.h>
#include <windows.h>

#include "maskaddr.h"

/* See https://docs.microsoft.com/en-us/windows/win32/services/service-programs */

#define SERVICE_NAME "MaskAddress"

/* The service control manager handle for use when running as a service. */
static SERVICE_STATUS_HANDLE h = NULL;

/* Used as SetServiceStatus argument. */
static SERVICE_STATUS service_status = {
	SERVICE_WIN32_OWN_PROCESS,
	0,
	SERVICE_CONTROL_INTERROGATE|SERVICE_ACCEPT_STOP,
	NO_ERROR, 0, 0, 0
};

/*
 * The handler is registered by service_main and invoked by control dispatcher
 * in a separate thread when an event occurs.
 */
static DWORD WINAPI service_handler(
  DWORD control, DWORD event_type,
  LPVOID event_data, LPVOID ctx
) {
	(void)event_type, (void)event_data, (void)ctx;
	switch(control) {
	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	case SERVICE_CONTROL_STOP:
		stop_maskaddr();
		service_status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(h, &service_status);
		return NO_ERROR;
	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

/*
 * The main function of the service should register the control handler, then
 * perform the work it is designed to perform.
 */
static void WINAPI service_main(DWORD argc, LPSTR *argv) {
	int ret;

	(void)argc, (void)argv;

	h = RegisterServiceCtrlHandlerEx(
		SERVICE_NAME, &service_handler, NULL
	);
	/* NB: In theory, we may get ERROR_NOT_ENOUGH_MEMORY for our ANSI string. */
	assert(h);

	service_status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(h, &service_status);

	ret = do_maskaddr(); /* Blocks until stop_maskaddr() is called. */
	if (ret) {
		service_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		service_status.dwServiceSpecificExitCode = ret;
	}

	service_status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(h, &service_status);
}

/*
 * This is called when the process is invoked normally
 * to (un)install the service.
 */
static int manage_service(int do_install) {
	int ret;
	SC_HANDLE hs = NULL, h = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!h) return GetLastError();
	if (do_install) {
		enum { cmdline_size = 4096 };
		static const char cmdline_end[] = "\" -service";
		/* cmdline is path to executable wrapped in quotes + arguments */
		char cmdline[1 + cmdline_size + sizeof cmdline_end] = "\"";
		/*
		 * In theory, we may get up to MAX_PATH characters. Or an error if the
		 * Unicode path is not representable in ANSI and there's no short name.
		 * TODO: switch to W API instead of A
		 */
		if (GetModuleFileName(NULL, cmdline + 1, cmdline_size) == cmdline_size) {
			ret = -2;
			goto cleanup;
		}
		strcat(cmdline, cmdline_end);
		hs = CreateService(
			h, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
			cmdline, NULL, NULL, "tcpip\0", NULL, NULL
		);
		ret = hs ? 0 : GetLastError();
	} else {
		hs = OpenService(h, SERVICE_NAME, SERVICE_ALL_ACCESS);
		if (!hs) {
			ret = GetLastError();
			goto cleanup;
		}
		ret = DeleteService(hs) ? 0 : GetLastError();
	}

cleanup:
	if (hs) CloseServiceHandle(hs);
	CloseServiceHandle(h);
	return ret;
}

static const SERVICE_TABLE_ENTRY sst[] = {
	{ "", &service_main },
	{ NULL, NULL }
};

int main(int argc, char ** argv) {
	if (argc != 2) {
		return -1;
	}
	if (!strcmp(argv[1], "-service")) {
		/* This starts up the service and blocks until it's stopped. */
		return StartServiceCtrlDispatcher(sst) ? 0 : GetLastError();
	} else if (!strcmp(argv[1], "-install")) {
		return manage_service(1);
	} else if (!strcmp(argv[1], "-uninstall")) {
		return manage_service(0);
	} else {
		return -1;
	}
}
