// RUN: %clang_cc1 %s -verify -fsyntax-only

// Test that we recover gracefully from conflict markers left in input files.
// PR5238

// diff3 style  expected-error@+1 {{version control conflict marker in file}}
float x = 17;

// normal style  expected-error@+1 {{version control conflict marker in file}}
typedef struct foo *y;

// Perforce style  expected-error@+1 {{version control conflict marker in file}}
>>>> ORIGINAL conflict-marker.c#6
int z = 1;
==== THEIRS conflict-marker.c#7
int z = 0;
==== YOURS conflict-marker.c
int z = 2;
<<<<

;
y b;


int foo() {
  y a = x;
  return x + a - z;
}

<<<<<<<>>>>>>> // expected-error {{expected identifier}}
