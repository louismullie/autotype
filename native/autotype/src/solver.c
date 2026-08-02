#include "../include/stc.h"

#include <stdlib.h>
#include <string.h>

stc_solver *stc_solver_new(void) {
  stc_solver *solver = calloc(1, sizeof(stc_solver));
  return solver;
}

static void stc_free_capabilities(stc_capability *caps, size_t count) {
  if (!caps) return;
  for (size_t c = 0; c < count; c++) {
    free(caps[c].args);
  }
  free(caps);
}

void stc_solver_free(stc_solver *solver) {
  if (!solver) return;
  for (size_t m = 0; m < solver->method_count; m++) {
    stc_free_capabilities(solver->methods[m].capabilities, solver->methods[m].capability_count);
  }
  free(solver->methods);
  free(solver->vars);
  free(solver->subs);
  if (solver->type_pool) {
    for (size_t i = 0; i < solver->type_pool_count; i++) {
      stc_type *type = solver->type_pool[i];
      if (type->kind == STC_TY_GENERIC) free(type->as.generic.args);
      if (type->kind == STC_TY_UNION) free(type->as.union_.members);
      free(type);
    }
    free(solver->type_pool);
  }
  free(solver);
}

void stc_solver_load_flat(stc_solver *solver, stc_capability *capabilities, size_t capability_count) {
  stc_method *method = calloc(1, sizeof(stc_method));
  if (!method) return;
  strncpy(method->name, "flat", STC_MAX_NAME - 1);
  method->capabilities = capabilities;
  method->capability_count = capability_count;
  solver->methods = method;
  solver->method_count = 1;
}

static bool stc_is_array(stc_solver *solver, stc_type *type) {
  type = stc_dereference(solver, type);
  return type && type->kind == STC_TY_GENERIC && strcmp(type->as.generic.name, "Array") == 0;
}

static bool stc_is_hash(stc_solver *solver, stc_type *type) {
  type = stc_dereference(solver, type);
  return type && type->kind == STC_TY_GENERIC && strcmp(type->as.generic.name, "Hash") == 0 &&
         type->as.generic.arg_count == 2;
}

static bool stc_is_string(stc_solver *solver, stc_type *type) {
  type = stc_dereference(solver, type);
  return type && type->kind == STC_TY_NAMED && strcmp(type->as.named.name, "String") == 0;
}

static stc_type *stc_array_element(stc_solver *solver, stc_type *type) {
  type = stc_dereference(solver, type);
  if (!stc_is_array(solver, type)) return NULL;
  return type->as.generic.args[0];
}

static stc_type *stc_enumerable_element(stc_solver *solver, stc_type *type) {
  type = stc_dereference(solver, type);
  if (!type) return NULL;
  if (stc_is_array(solver, type)) return stc_array_element(solver, type);
  if (stc_is_hash(solver, type)) return type->as.generic.args[1];
  return NULL;
}

static stc_type *stc_nil(stc_solver *solver) {
  return stc_type_named(solver, "nil");
}

static stc_type *stc_nullable(stc_solver *solver, stc_type *type) {
  stc_type *nil = stc_nil(solver);
  stc_type *members[] = { type, nil };
  return stc_type_union(solver, members, 2);
}

static void stc_unify_array_elements(stc_solver *solver, stc_type *receiver, stc_type *argument) {
  stc_type *element = stc_array_element(solver, receiver);
  if (element) stc_unify(solver, element, argument);
}

void stc_apply_builtin(stc_solver *solver, stc_capability *capability) {
  stc_type *receiver = stc_dereference(solver, capability->receiver);
  stc_type *result = capability->result;
  const char *message = capability->message;

  if (strcmp(message, "to_s") == 0 || strcmp(message, "inspect") == 0 || strcmp(message, "String") == 0) {
    stc_unify(solver, result, stc_type_named(solver, "String"));
    return;
  }
  if (strcmp(message, "to_i") == 0 || strcmp(message, "ord") == 0 || strcmp(message, "Integer") == 0 ||
      strcmp(message, "size") == 0 || strcmp(message, "length") == 0 || strcmp(message, "count") == 0) {
    stc_unify(solver, result, stc_type_named(solver, "Integer"));
    return;
  }
  if (strcmp(message, "to_f") == 0 || strcmp(message, "Float") == 0 || strcmp(message, "clock_gettime") == 0) {
    stc_unify(solver, result, stc_type_named(solver, "Float"));
    return;
  }
  if (strcmp(message, "to_sym") == 0) {
    stc_unify(solver, result, stc_type_named(solver, "Symbol"));
    return;
  }
  if (strcmp(message, "!") == 0 || strcmp(message, "present?") == 0 || strcmp(message, "blank?") == 0 ||
      strcmp(message, "nil?") == 0 || strcmp(message, "empty?") == 0 || strcmp(message, "any?") == 0 ||
      strcmp(message, "all?") == 0 || strcmp(message, "none?") == 0 || strcmp(message, "include?") == 0 ||
      strcmp(message, "key?") == 0 || strcmp(message, "has_key?") == 0) {
    stc_unify(solver, result, stc_type_named(solver, "bool"));
    return;
  }
  if (strcmp(message, "puts") == 0 || strcmp(message, "print") == 0 || strcmp(message, "p") == 0) {
    stc_unify(solver, result, stc_nil(solver));
    return;
  }
  if (strcmp(message, "tap") == 0 || strcmp(message, "itself") == 0 || strcmp(message, "deep_dup") == 0 ||
      strcmp(message, "dup") == 0 || strcmp(message, "clone") == 0 || strcmp(message, "freeze") == 0 ||
      strcmp(message, "with") == 0) {
    stc_unify(solver, result, receiver);
    return;
  }
  if (strcmp(message, "presence") == 0) {
    stc_unify(solver, result, stc_nullable(solver, receiver));
    return;
  }
  if (strcmp(message, "[]") == 0) {
    if (stc_is_hash(solver, receiver) && capability->arg_count >= 1) {
      stc_type *value = receiver->as.generic.args[1];
      stc_unify(solver, result, stc_nullable(solver, value));
      return;
    }
    if (stc_is_array(solver, receiver) && capability->arg_count >= 1) {
      stc_type *element = stc_array_element(solver, receiver);
      if (element) stc_unify(solver, result, stc_nullable(solver, element));
      return;
    }
  }
  if ((strcmp(message, "<<") == 0 || strcmp(message, "push") == 0 || strcmp(message, "append") == 0 ||
       strcmp(message, "unshift") == 0 || strcmp(message, "prepend") == 0) &&
      stc_is_array(solver, receiver)) {
    for (size_t i = 0; i < capability->arg_count; i++) {
      stc_unify_array_elements(solver, receiver, capability->args[i]);
    }
    stc_unify(solver, result, receiver);
    return;
  }
  if (strcmp(message, "<<") == 0 && stc_is_string(solver, receiver)) {
    stc_unify(solver, result, receiver);
    return;
  }
  if (strcmp(message, "concat") == 0) {
    if (stc_is_array(solver, receiver)) {
      for (size_t i = 0; i < capability->arg_count; i++) {
        stc_unify(solver, receiver, capability->args[i]);
      }
      stc_unify(solver, result, receiver);
      return;
    }
    if (stc_is_string(solver, receiver)) {
      stc_unify(solver, result, receiver);
      return;
    }
  }
  if (strcmp(message, "keys") == 0 && stc_is_hash(solver, receiver)) {
    stc_type *args[] = { receiver->as.generic.args[0] };
    stc_unify(solver, result, stc_type_generic(solver, "Array", args, 1));
    return;
  }
  if (strcmp(message, "values") == 0 && stc_is_hash(solver, receiver)) {
    stc_type *args[] = { receiver->as.generic.args[1] };
    stc_unify(solver, result, stc_type_generic(solver, "Array", args, 1));
    return;
  }
  if (strcmp(message, "sort") == 0 || strcmp(message, "sort_by") == 0 || strcmp(message, "reverse") == 0 ||
      strcmp(message, "take") == 0 || strcmp(message, "drop") == 0 || strcmp(message, "uniq") == 0 ||
      strcmp(message, "shuffle") == 0 || strcmp(message, "rotate") == 0 || strcmp(message, "to_a") == 0 ||
      strcmp(message, "each") == 0 || strcmp(message, "each_value") == 0 || strcmp(message, "each_key") == 0 ||
      strcmp(message, "each_pair") == 0) {
    if (stc_is_array(solver, receiver) || stc_is_hash(solver, receiver)) {
      stc_unify(solver, result, receiver);
      return;
    }
  }
  if ((strcmp(message, "merge") == 0 || strcmp(message, "merge!") == 0 || strcmp(message, "except") == 0 ||
       strcmp(message, "slice") == 0 || strcmp(message, "deep_symbolize_keys") == 0 ||
       strcmp(message, "symbolize_keys") == 0 || strcmp(message, "with_indifferent_access") == 0) &&
      stc_is_hash(solver, receiver)) {
    stc_unify(solver, result, receiver);
    return;
  }
  if (strcmp(message, "deep_stringify_keys") == 0 || strcmp(message, "stringify_keys") == 0) {
    if (stc_is_hash(solver, receiver)) {
      stc_type *args[] = { stc_type_named(solver, "String"), receiver->as.generic.args[1] };
      stc_unify(solver, result, stc_type_generic(solver, "Hash", args, 2));
      return;
    }
  }
  if (strcmp(message, "to_h") == 0 || strcmp(message, "to_hash") == 0) {
    if (stc_is_hash(solver, receiver)) {
      stc_unify(solver, result, receiver);
      return;
    }
  }
  if (strcmp(message, "flatten") == 0 && stc_is_array(solver, receiver)) {
    stc_type *element = stc_array_element(solver, receiver);
    if (element) {
      stc_type *inner = stc_array_element(solver, element);
      stc_type *flat = inner ? inner : element;
      stc_type *args[] = { flat };
      stc_unify(solver, result, stc_type_generic(solver, "Array", args, 1));
    }
    return;
  }
  if ((strcmp(message, "first") == 0 || strcmp(message, "last") == 0 || strcmp(message, "min") == 0 ||
       strcmp(message, "max") == 0 || strcmp(message, "find") == 0 || strcmp(message, "detect") == 0 ||
       strcmp(message, "sample") == 0)) {
    stc_type *element = stc_enumerable_element(solver, receiver);
    if (element) stc_unify(solver, result, stc_nullable(solver, element));
    return;
  }
  if (strcmp(message, "delete") == 0 && stc_is_hash(solver, receiver) && capability->arg_count >= 1) {
    stc_type *value = receiver->as.generic.args[1];
    stc_unify(solver, result, stc_nullable(solver, value));
    return;
  }
  if (strcmp(message, "fetch") == 0 && stc_is_hash(solver, receiver)) {
    stc_type *value = receiver->as.generic.args[1];
    stc_unify(solver, result, value);
    return;
  }
  if (strcmp(message, "dig") == 0 && stc_is_hash(solver, receiver)) {
    stc_unify(solver, result, stc_type_named(solver, "Object"));
    return;
  }
  if (strcmp(message, "join") == 0 && stc_is_array(solver, receiver)) {
    stc_unify(solver, result, stc_type_named(solver, "String"));
    return;
  }
  if (strcmp(message, "split") == 0 && stc_is_string(solver, receiver)) {
    stc_type *args[] = { stc_type_named(solver, "String") };
    stc_unify(solver, result, stc_type_generic(solver, "Array", args, 1));
    return;
  }
  if (strcmp(message, "strip") == 0 || strcmp(message, "downcase") == 0 || strcmp(message, "upcase") == 0 ||
      strcmp(message, "capitalize") == 0 || strcmp(message, "squeeze") == 0) {
    if (stc_is_string(solver, receiver)) {
      stc_unify(solver, result, receiver);
      return;
    }
  }
  if ((strcmp(message, "+") == 0 || strcmp(message, "-") == 0 || strcmp(message, "*") == 0 ||
       strcmp(message, "/") == 0 || strcmp(message, "%") == 0) &&
      receiver && receiver->kind == STC_TY_NAMED) {
    const char *name = receiver->as.named.name;
    if (strcmp(name, "Integer") == 0 || strcmp(name, "Float") == 0 || strcmp(name, "String") == 0) {
      stc_unify(solver, result, receiver);
      return;
    }
  }
  if ((strcmp(message, "+") == 0 || strcmp(message, "-") == 0) && stc_is_array(solver, receiver)) {
    stc_unify(solver, result, receiver);
  }
}

void stc_solve_to_fixed_point(stc_solver *solver) {
  for (int iteration = 0; iteration < STC_MAX_ITERATIONS; iteration++) {
    solver->changed = 0;
    for (size_t m = 0; m < solver->method_count; m++) {
      stc_method *method = &solver->methods[m];
      for (size_t c = 0; c < method->capability_count; c++) {
        stc_apply_builtin(solver, &method->capabilities[c]);
      }
    }
    solver->iterations = iteration + 1;
    if (!solver->changed) {
      solver->converged = 1;
      break;
    }
  }
}

int stc_solver_run(stc_solver *solver) {
  stc_solve_to_fixed_point(solver);
  return solver->converged;
}
