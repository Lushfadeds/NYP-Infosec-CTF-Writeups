#include <stdio.h>
#include <unistd.h>

void setup() {
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
}

int get_input() {
  char info[0x20];
  puts("Tell me more about your pokemon");
  read(0, info, 0x100);
  return 0;
}

int vuln() {
  char pokemon[0x10];
  puts("What is your favourite pokemon?");
  fgets(pokemon, sizeof(pokemon), stdin);
  puts("I see you like...");
  printf(pokemon);
  return 0;
}

int main() {
  setup();
  vuln();
  get_input();
  return 0;
}
