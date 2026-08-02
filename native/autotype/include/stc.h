#ifndef STC_H
#define STC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STC_MAX_NAME 256
#define STC_MAX_ITERATIONS 64

typedef uint64_t stc_var_id;

typedef enum {
  STC_TY_NIL = 0,
  STC_TY_NAMED,
  STC_TY_VAR,
  STC_TY_GENERIC,
  STC_TY_UNION
} stc_type_kind;

typedef struct stc_type stc_type;

struct stc_type {
  stc_type_kind kind;
  union {
    struct { char name[STC_MAX_NAME]; } named;
    struct { stc_var_id id; char hint[64]; } var;
    struct {
      char name[32];
      stc_type **args;
      size_t arg_count;
    } generic;
    struct {
      stc_type **members;
      size_t member_count;
    } union_;
  } as;
};

typedef struct {
  stc_var_id id;
  char hint[64];
} stc_var;

typedef struct {
  stc_type *receiver;
  stc_type *result;
  char message[64];
  stc_type **args;
  size_t arg_count;
  int32_t line;
} stc_capability;

typedef struct {
  char name[STC_MAX_NAME];
  char owner[STC_MAX_NAME];
  stc_type *result;
  stc_capability *capabilities;
  size_t capability_count;
} stc_method;

typedef struct {
  stc_var_id var_id;
  stc_type *type;
} stc_substitution;

typedef struct {
  stc_var *vars;
  size_t var_count;

  stc_method *methods;
  size_t method_count;

  stc_substitution *subs;
  size_t sub_count;
  size_t sub_cap;

  stc_type **type_pool;
  size_t type_pool_count;
  size_t type_pool_cap;

  int32_t changed;
  int32_t iterations;
  int32_t converged;
} stc_solver;

stc_solver *stc_solver_new(void);
void stc_solver_free(stc_solver *solver);

stc_type *stc_type_named(stc_solver *solver, const char *name);
stc_type *stc_type_var(stc_solver *solver, stc_var_id id, const char *hint);
stc_type *stc_type_generic(stc_solver *solver, const char *name, stc_type **args, size_t arg_count);
stc_type *stc_type_union(stc_solver *solver, stc_type **members, size_t member_count);

stc_type *stc_dereference(stc_solver *solver, stc_type *type);
stc_type *stc_resolve(stc_solver *solver, stc_type *type);

void stc_unify(stc_solver *solver, stc_type *left, stc_type *right);
void stc_bind(stc_solver *solver, stc_var_id var_id, stc_type *type);

void stc_apply_builtin(stc_solver *solver, stc_capability *capability);
void stc_solve_to_fixed_point(stc_solver *solver);
int stc_solver_run(stc_solver *solver);

void stc_solver_load_flat(stc_solver *solver, stc_capability *capabilities, size_t capability_count);

#endif
