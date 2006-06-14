/* $Id$ */

#include <rtems.h>
#include <stdio.h>
#include <cexp.h>
#include "rtems-gdb-stub.h"

int
_cexpModuleFinalize(void *h)
{
	if ( rtems_gdb_nounload ) {
		fprintf(stderr,"GDB module cannot be unloaded (e.g., because exception handler cannot be disconnected)\n");
		return -1;
	}
	if ( rtems_gdb_tid ) {
		fprintf(stderr,"GDB daemon still running; refuse to unload - use rtems_gdb_stop() first\n");
		return -1;
	}
	return 0;
}

/*
void
_cexpModuleInitialize(void *h)
{
 	rtems_gdb_start(40,0);
}
*/
