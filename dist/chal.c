#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
}

int vuln() {
  char buf[32];
  puts("Welcome to the easiest pwn chall you are getting");
  read(0, buf, 64);
  return 0;
}

int main() {
  setup();
  vuln();
  return 0;
}

void win() { system("/bin/sh"); }
