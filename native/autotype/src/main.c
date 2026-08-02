#include "../include/stc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal smoke-test driver for the native solver core. */
int main(void) {
  stc_solver *solver = stc_solver_new();
  if (!solver) return 1;

  stc_capability *caps = calloc(2, sizeof(stc_capability));
  if (!caps) return 1;

  caps[0].receiver = stc_type_var(solver, 1, "hash");
  caps[0].result = stc_type_var(solver, 2, "array");
  strncpy(caps[0].message, "[]", sizeof(caps[0].message) - 1);
  caps[0].args = malloc(sizeof(stc_type *));
  caps[0].args[0] = stc_type_var(solver, 3, "key");
  caps[0].arg_count = 1;

  caps[1].receiver = stc_type_var(solver, 2, "array");
  caps[1].result = stc_type_var(solver, 10, "result");
  strncpy(caps[1].message, "<<", sizeof(caps[1].message) - 1);
  caps[1].args = malloc(sizeof(stc_type *));
  caps[1].args[0] = stc_type_var(solver, 4, "item");
  caps[1].arg_count = 1;

  stc_solver_load_flat(solver, caps, 2);

  stc_type *key = stc_type_named(solver, "Integer");
  stc_type *element = stc_type_var(solver, 99, "element");
  stc_type *hash_args[] = { key, stc_type_generic(solver, "Array", &element, 1) };
  stc_type *hash_type = stc_type_generic(solver, "Hash", hash_args, 2);
  stc_bind(solver, 1, hash_type);

  stc_type *item = stc_type_named(solver, "Widget");
  stc_bind(solver, 4, item);

  stc_solver_run(solver);

  stc_type *resolved = stc_resolve(solver, stc_type_var(solver, 10, "result"));
  printf("converged=%d iterations=%d\n", solver->converged, solver->iterations);
  if (resolved && resolved->kind == STC_TY_GENERIC) {
    printf("result=%s\n", resolved->as.generic.name);
  }

  stc_solver_free(solver);
  return 0;
}
