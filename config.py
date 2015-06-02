import os

LINKDIR = os.path.normpath(os.getcwd())

CROSS_TOOL 	= 'gcc'

if  CROSS_TOOL == 'gcc':
	PLATFORM 	= 'gcc'
	#EXEC_PATH 	= '/opt/arm-2011.09/bin/'

BUILD = 'debug'

if PLATFORM == 'gcc':
    # toolchains
    PREFIX = ''
    CC = PREFIX + 'gcc'
    AS = PREFIX + 'gcc'
    AR = PREFIX + 'ar'
    LINK = PREFIX + 'gcc'
    SIZE = PREFIX + 'size'
    OBJDUMP = PREFIX + 'objdump'
    OBJCPY = PREFIX + 'objcopy'

    CFLAGS = ''
    #AFLAGS = ' -c' + ' -x assembler-with-cpp'
    LFLAGS = ''

    CPATH = ''
    LPATH = ''

    if BUILD == 'debug':
        CFLAGS += ' -O0 -gdwarf-2'
        #AFLAGS += ' -gdwarf-2'
    else:
        CFLAGS += ' -O2'

    #POST_ACTION = OBJCPY + ' -O binary $TARGET ftpd.bin\n' + SIZE + ' $TARGET \n'

