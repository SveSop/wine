#include <stdio.h>
#include <stdlib.h>
#include "registers.h"
#include "wine.h"
#include "miscemu.h"
#include "stddebug.h"
/* #define DEBUG_INT */
#include "debug.h"


/**********************************************************************
 *	    INT_Int10Handler
 *
 * Handler for int 10h (video).
 */
void INT_Int10Handler( struct sigcontext_struct sigcontext )
{
#define context (&sigcontext)
    switch(AH)
    {
    case 0x0f:
        AL = 0x5b;
        break;

    case 0x12:
        if (BL == 0x10)
        {
            BX = 0x0003;
            CX = 0x0009;
        }
        break;
			
    case 0x1a:
        BX = 0x0008;
        break;

    default:
        INT_BARF( 0x10 );
    }
#undef context
}
