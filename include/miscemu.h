#ifndef __WINE_MISCEMU_H
#define __WINE_MISCEMU_H

#include "wintypes.h"
#include "wine.h"

extern BOOL INSTR_EmulateInstruction( struct sigcontext_struct *context );

extern DWORD inport( int port, int count );
extern void outport( int port, int count, DWORD value );

extern BOOL INT_Init(void);
extern SEGPTR INT_GetHandler( BYTE intnum );
extern void INT_SetHandler( BYTE intnum, SEGPTR handler );

extern void INT21_Init(void);


#define INT_BARF(num) \
    fprintf( stderr, "int%x: unknown/not implemented parameters:\n" \
                     "int%x: AX %04x, BX %04x, CX %04x, DX %04x, " \
                     "SI %04x, DI %04x, DS %04x, ES %04x\n", \
             (num), (num), AX, BX, CX, DX, SI, DI, DS, ES )

#endif /* __WINE_MISCEMU_H */
