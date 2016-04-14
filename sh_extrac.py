"""
Autor: P3tr1
email: p3tr1qs@gmail.com
version: 0.1-alpha
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

import sys
import getopt
from ctypes import *
import binascii

template_c_linux = """
//compile command: gcc -o %s -fno-stack-protector -z execstack %s
char code[] = "%s";
int main(int argc, char **argv)
{
  int (*func)();
  func = (int (*)()) code;
  (int)(*func)();
}
"""

def execute(shellcode):
    PROT_NONE = 0x0
    PROT_READ = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC = 0x4

    shellcode = shellcode.replace("\\x",'')
    shellcode = binascii.a2b_hex(shellcode)


    libc = CDLL("libc.so.6")
    buf = c_char_p(shellcode)
    size = len(shellcode)
    addr = libc.valloc(size)
    addr = c_void_p(addr)
    if 0 == addr:  
        raise Exception("Failed to allocate memory")
    memmove(addr, buf, size)
    if 0 != libc.mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC):
        raise Exception("Failed to set protection on buffer")

    code_ptr = addr
    fptr = cast(code_ptr, CFUNCTYPE(c_long, c_long))
    print(fptr(1234))
    libc.free(code_ptr)

def extract(bf):
    file = open(bf,'r')
    flag = False
 
    aux = ''
    for f in file:
        if not flag:
           if ".text" in f:
               flag = True
           continue
        if not ":\t" in f:
           continue
        beg = f.find('\t')+1
        shcd = f[beg:]
        end = shcd.find('\t')+1
        shcd = shcd[:end]
        shcd = shcd.rstrip()
        shcd = shcd.split(" ");

        for s in shcd:
            s.rstrip()
            aux += "\\x"+s

    return aux

def write_linux_code(filename,shellcode):

    fd = open(filename,'w')
    content = template_c_linux % (filename[:-2],filename,shellcode)
    fd.write(content)
    fd.close()

def main(argv):
   
    try:
        opts,args = getopt.getopt(argv,"heb:c:",['binfile='])
    except getopt.GetoptError:
        print('sh-extract.py -b <inputfile>')
        sys.exit(2)
    sh_code = ''
    for opt, arg in opts:
        if opt == '-h':
            print('sh=extract.py -b <inputfile>')
            sys.exit()
        elif opt in ("-b", "--binfile"):
            sh_code = extract(arg)
        elif opt in ("-c","--c_code"):
            write_linux_code(arg,sh_code)
        elif opt in ("-e"):
            execute(sh_code)


if __name__ == "__main__":
   main(sys.argv[1:])
