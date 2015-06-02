import config
from SCons.Script import *

Import('env')

inc_path = ['./']

#src = Split("""
#""")
src = ['ftpd.c']

env.Append(CPPPATH = inc_path)

objs = env.Object(src)

Return('objs')
