#include "../include/stc.h"

#include <stdlib.h>
#include <string.h>

static stc_type *stc_alloc_type(stc_solver *solver) {
  stc_type *type = calloc(1, sizeof(stc_type));
  if (!type) return NULL;

  if (solver->type_pool_count >= solver->type_pool_cap) {
    size_t new_cap = solver->type_pool_cap == 0 ? 256 : solver->type_pool_cap * 2;
    stc_type **new_pool = realloc(solver->type_pool, new_cap * sizeof(stc_type *));
    if (!new_pool) {
      free(type);
      return NULL;
    }
    solver->type_pool = new_pool;
    solver->type_pool_cap = new_cap;
  }

  solver->type_pool[solver->type_pool_count++] = type;
  return type;
}

stc_type *stc_type_named(stc_solver *solver, const char *name) {
  stc_type *type = stc_alloc_type(solver);
  if (!type) return NULL;
  type->kind = STC_TY_NAMED;
  strncpy(type->as.named.name, name, STC_MAX_NAME - 1);
  return type;
}

stc_type *stc_type_var(stc_solver *solver, stc_var_id id, const char *hint) {
  stc_type *type = stc_alloc_type(solver);
  if (!type) return NULL;
  type->kind = STC_TY_VAR;
  type->as.var.id = id;
  if (hint) strncpy(type->as.var.hint, hint, sizeof(type->as.var.hint) - 1);
  return type;
}

stc_type *stc_type_generic(stc_solver *solver, const char *name, stc_type **args, size_t arg_count) {
  stc_type *type = stc_alloc_type(solver);
  if (!type) return NULL;
  stc_type **owned_args = NULL;
  if (arg_count > 0) {
    owned_args = calloc(arg_count, sizeof(stc_type *));
    if (!owned_args) return NULL;
    memcpy(owned_args, args, arg_count * sizeof(stc_type *));
  }
  type->kind = STC_TY_GENERIC;
  strncpy(type->as.generic.name, name, sizeof(type->as.generic.name) - 1);
  type->as.generic.args = owned_args;
  type->as.generic.arg_count = arg_count;
  return type;
}

stc_type *stc_type_union(stc_solver *solver, stc_type **members, size_t member_count) {
  stc_type *type = stc_alloc_type(solver);
  if (!type) return NULL;
  stc_type **owned_members = NULL;
  if (member_count > 0) {
    owned_members = calloc(member_count, sizeof(stc_type *));
    if (!owned_members) return NULL;
    memcpy(owned_members, members, member_count * sizeof(stc_type *));
  }
  type->kind = STC_TY_UNION;
  type->as.union_.members = owned_members;
  type->as.union_.member_count = member_count;
  return type;
}

static stc_type *stc_find_sub(stc_solver *solver, stc_var_id var_id) {
  for (size_t i = 0; i < solver->sub_count; i++) {
    if (solver->subs[i].var_id == var_id) return solver->subs[i].type;
  }
  return NULL;
}

stc_type *stc_dereference(stc_solver *solver, stc_type *type) {
  stc_var_id seen[64];
  size_t seen_count = 0;

  while (type && type->kind == STC_TY_VAR) {
    for (size_t i = 0; i < seen_count; i++) {
      if (seen[i] == type->as.var.id) return type;
    }
    if (seen_count < 64) seen[seen_count++] = type->as.var.id;

    stc_type *next = stc_find_sub(solver, type->as.var.id);
    if (!next) break;
    type = next;
  }
  return type;
}

static bool stc_same_type(stc_type *left, stc_type *right) {
  if (!left || !right) return left == right;
  if (left->kind != right->kind) return false;
  switch (left->kind) {
    case STC_TY_NAMED:
      return strcmp(left->as.named.name, right->as.named.name) == 0;
    case STC_TY_VAR:
      return left->as.var.id == right->as.var.id;
    case STC_TY_GENERIC:
      if (strcmp(left->as.generic.name, right->as.generic.name) != 0) return false;
      if (left->as.generic.arg_count != right->as.generic.arg_count) return false;
      for (size_t i = 0; i < left->as.generic.arg_count; i++) {
        if (!stc_same_type(left->as.generic.args[i], right->as.generic.args[i])) return false;
      }
      return true;
    case STC_TY_UNION:
      if (left->as.union_.member_count != right->as.union_.member_count) return false;
      for (size_t i = 0; i < left->as.union_.member_count; i++) {
        if (!stc_same_type(left->as.union_.members[i], right->as.union_.members[i])) return false;
      }
      return true;
    default:
      return false;
  }
}

static stc_type *stc_resolve_inner(stc_solver *solver, stc_type *type, stc_var_id *seen, size_t *seen_count, int depth);

stc_type *stc_resolve(stc_solver *solver, stc_type *type) {
  stc_var_id seen[64];
  size_t seen_count = 0;
  return stc_resolve_inner(solver, type, seen, &seen_count, 0);
}

static stc_type *stc_resolve_inner(stc_solver *solver, stc_type *type, stc_var_id *seen, size_t *seen_count, int depth) {
  if (!type || depth > 24) return type;

  if (type->kind == STC_TY_VAR) {
    for (size_t i = 0; i < *seen_count; i++) {
      if (seen[i] == type->as.var.id) return type;
    }
    if (*seen_count < 64) seen[(*seen_count)++] = type->as.var.id;
  }

  type = stc_dereference(solver, type);
  if (!type) return NULL;

  if (type->kind == STC_TY_GENERIC) {
    stc_type **args = calloc(type->as.generic.arg_count, sizeof(stc_type *));
    if (!args) return type;
    for (size_t i = 0; i < type->as.generic.arg_count; i++) {
      args[i] = stc_resolve_inner(solver, type->as.generic.args[i], seen, seen_count, depth + 1);
    }
    return stc_type_generic(solver, type->as.generic.name, args, type->as.generic.arg_count);
  }

  if (type->kind == STC_TY_UNION) {
    stc_type **members = calloc(type->as.union_.member_count, sizeof(stc_type *));
    if (!members) return type;
    size_t out = 0;
    for (size_t i = 0; i < type->as.union_.member_count; i++) {
      stc_type *resolved = stc_resolve_inner(solver, type->as.union_.members[i], seen, seen_count, depth + 1);
      if (!resolved) continue;
      bool dup = false;
      for (size_t j = 0; j < out; j++) {
        if (stc_same_type(members[j], resolved)) { dup = true; break; }
      }
      if (!dup) members[out++] = resolved;
    }
    if (out == 0) return type;
    if (out == 1) return members[0];
    return stc_type_union(solver, members, out);
  }

  return type;
}

void stc_bind(stc_solver *solver, stc_var_id var_id, stc_type *type) {
  stc_type *existing = stc_find_sub(solver, var_id);
  if (existing && stc_same_type(existing, type)) return;

  if (solver->sub_count >= solver->sub_cap) {
    size_t new_cap = solver->sub_cap == 0 ? 256 : solver->sub_cap * 2;
    stc_substitution *new_subs = realloc(solver->subs, new_cap * sizeof(stc_substitution));
    if (!new_subs) return;
    solver->subs = new_subs;
    solver->sub_cap = new_cap;
  }

  /* Update in place if already bound. */
  for (size_t i = 0; i < solver->sub_count; i++) {
    if (solver->subs[i].var_id == var_id) {
      solver->subs[i].type = type;
      solver->changed = 1;
      return;
    }
  }

  solver->subs[solver->sub_count].var_id = var_id;
  solver->subs[solver->sub_count].type = type;
  solver->sub_count++;
  if (type->kind != STC_TY_VAR) solver->changed = 1;
}

void stc_unify(stc_solver *solver, stc_type *left, stc_type *right) {
  if (!left || !right) return;
  left = stc_dereference(solver, left);
  right = stc_dereference(solver, right);
  if (stc_same_type(left, right)) return;

  if (left->kind == STC_TY_VAR) {
    stc_bind(solver, left->as.var.id, right);
    return;
  }
  if (right->kind == STC_TY_VAR) {
    stc_bind(solver, right->as.var.id, left);
    return;
  }

  if (left->kind == STC_TY_GENERIC && right->kind == STC_TY_GENERIC &&
      strcmp(left->as.generic.name, right->as.generic.name) == 0 &&
      left->as.generic.arg_count == right->as.generic.arg_count) {
    for (size_t i = 0; i < left->as.generic.arg_count; i++) {
      stc_unify(solver, left->as.generic.args[i], right->as.generic.args[i]);
    }
  }
}
