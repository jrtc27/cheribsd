/**
 * Check where the stack ends up to see if libprocstat is giving the correct reading.
 */

/* #include <sys/types.h> */
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc __unused, char *argv[] __unused)
{

  /* get stack pointer */
  uint64_t stack;
  uint64_t cap_stack;

  asm("move %0, $sp"
      : "=r" (stack));
  asm("cgetdefault $c15\n\t"
      "ctoptr %0, $c11, $c15"
      : "=r" (cap_stack)
      :: "$c15");

  printf("Current pid %lu\n", (unsigned long)getpid());
  printf("Stack pointer: 0x%0.16" PRIx64 "\n", stack);
  printf("Capability stack pointer: 0x%0.16" PRIx64 "\n", cap_stack);

  return 0;
}
