import os
import sys
import config

from SCons.Script import *

TARGET = 'ftpd'

env = Environment(tools = ['mingw'],
	AS = config.AS, #ASFLAGS = config.AFLAGS,
	CC = config.CC, CCFLAGS = config.CFLAGS,
	AR = config.AR, ARFLAGS = '-rc',
	LINK = config.LINK, LINKFLAGS = config.LFLAGS)
#env.PrependENVPath('PATH', config.EXEC_PATH)

Export('config')
Export('env')

objs = SConscript(['SConscript'], variant_dir='build', duplicate=0)

#env.Append(CPPPATH = inc_path)

#env.ParseConfig("pkg-config --libs --cflags gtk+-2.0 vte gthread-2.0")

# build program 
env.Program(TARGET, objs)

#env.AddPostAction(TARGET, config.POST_ACTION)

