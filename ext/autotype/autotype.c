/*
 * Ruby bindings for the native Autotype solver core.
 *
 * Exposes AutotypeNative.solve_graph for the fixed-point builtin
 * solver. Collection and rendering remain in Ruby.
 */

#include <ruby.h>
#include "../../native/autotype/include/stc.h"

extern stc_solver *stc_solver_new(void);
extern void stc_solver_free(stc_solver *solver);
extern void stc_solver_load_flat(stc_solver *solver, stc_capability *capabilities, size_t capability_count);
extern int stc_solver_run(stc_solver *solver);
extern stc_type *stc_resolve(stc_solver *solver, stc_type *type);

static VALUE stc_mAutotypeNative;
static VALUE stc_cSolver;

static VALUE stc_hash_get(VALUE hash, const char *key) {
  VALUE sym = ID2SYM(rb_intern(key));
  VALUE val = rb_hash_aref(hash, sym);
  if (!NIL_P(val)) return val;
  return rb_hash_aref(hash, rb_str_new2(key));
}

static stc_var_id stc_var_id_from_ruby(VALUE value) {
  return (stc_var_id)NUM2ULL(value);
}

static VALUE stc_var_id_to_ruby(stc_var_id id) {
  return ULL2NUM((unsigned long long)id);
}

static stc_type *stc_type_from_ruby(stc_solver *solver, VALUE hash) {
  VALUE kind = stc_hash_get(hash, "k");
  Check_Type(kind, T_STRING);
  const char *tag = StringValueCStr(kind);

  if (strcmp(tag, "named") == 0) {
    VALUE name = stc_hash_get(hash, "name");
    return stc_type_named(solver, StringValueCStr(name));
  }
  if (strcmp(tag, "var") == 0) {
    VALUE id = stc_hash_get(hash, "id");
    VALUE hint = stc_hash_get(hash, "hint");
    const char *hint_str = NIL_P(hint) ? NULL : StringValueCStr(hint);
    return stc_type_var(solver, stc_var_id_from_ruby(id), hint_str);
  }
  if (strcmp(tag, "generic") == 0) {
    VALUE name = stc_hash_get(hash, "name");
    VALUE args = stc_hash_get(hash, "args");
    long argc = RARRAY_LEN(args);
    stc_type **typed_args = calloc((size_t)argc, sizeof(stc_type *));
    if (!typed_args) return NULL;
    for (long i = 0; i < argc; i++) {
      typed_args[i] = stc_type_from_ruby(solver, rb_ary_entry(args, i));
    }
    return stc_type_generic(solver, StringValueCStr(name), typed_args, (size_t)argc);
  }
  if (strcmp(tag, "union") == 0) {
    VALUE members = stc_hash_get(hash, "members");
    long count = RARRAY_LEN(members);
    stc_type **typed_members = calloc((size_t)count, sizeof(stc_type *));
    if (!typed_members) return NULL;
    for (long i = 0; i < count; i++) {
      typed_members[i] = stc_type_from_ruby(solver, rb_ary_entry(members, i));
    }
    return stc_type_union(solver, typed_members, (size_t)count);
  }

  return stc_type_named(solver, "Object");
}

static VALUE stc_type_to_ruby_inner(stc_type *type, stc_var_id *seen, size_t *seen_count, int depth);

static VALUE stc_type_to_ruby(stc_type *type) {
  stc_var_id seen[64];
  size_t seen_count = 0;
  return stc_type_to_ruby_inner(type, seen, &seen_count, 0);
}

static VALUE stc_type_to_ruby_inner(stc_type *type, stc_var_id *seen, size_t *seen_count, int depth) {
  VALUE hash = rb_hash_new();
  if (!type || depth > 24) {
    rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("named"));
    rb_hash_aset(hash, ID2SYM(rb_intern("name")), rb_str_new2("Object"));
    return hash;
  }

  if (type->kind == STC_TY_VAR) {
    for (size_t i = 0; i < *seen_count; i++) {
      if (seen[i] == type->as.var.id) {
        rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("var"));
        rb_hash_aset(hash, ID2SYM(rb_intern("id")), stc_var_id_to_ruby(type->as.var.id));
        rb_hash_aset(hash, ID2SYM(rb_intern("hint")), rb_str_new2(type->as.var.hint));
        return hash;
      }
    }
    if (*seen_count < 64) seen[(*seen_count)++] = type->as.var.id;
  }

  switch (type->kind) {
    case STC_TY_NAMED:
      rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("named"));
      rb_hash_aset(hash, ID2SYM(rb_intern("name")), rb_str_new2(type->as.named.name));
      break;
    case STC_TY_VAR:
      rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("var"));
      rb_hash_aset(hash, ID2SYM(rb_intern("id")), stc_var_id_to_ruby(type->as.var.id));
      rb_hash_aset(hash, ID2SYM(rb_intern("hint")), rb_str_new2(type->as.var.hint));
      break;
    case STC_TY_GENERIC: {
      VALUE args = rb_ary_new_capa((long)type->as.generic.arg_count);
      for (size_t i = 0; i < type->as.generic.arg_count; i++) {
        rb_ary_push(args, stc_type_to_ruby_inner(type->as.generic.args[i], seen, seen_count, depth + 1));
      }
      rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("generic"));
      rb_hash_aset(hash, ID2SYM(rb_intern("name")), rb_str_new2(type->as.generic.name));
      rb_hash_aset(hash, ID2SYM(rb_intern("args")), args);
      break;
    }
    case STC_TY_UNION: {
      VALUE members = rb_ary_new_capa((long)type->as.union_.member_count);
      for (size_t i = 0; i < type->as.union_.member_count; i++) {
        rb_ary_push(members, stc_type_to_ruby_inner(type->as.union_.members[i], seen, seen_count, depth + 1));
      }
      rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("union"));
      rb_hash_aset(hash, ID2SYM(rb_intern("members")), members);
      break;
    }
    default:
      rb_hash_aset(hash, ID2SYM(rb_intern("k")), rb_str_new2("named"));
      rb_hash_aset(hash, ID2SYM(rb_intern("name")), rb_str_new2("Object"));
      break;
  }
  return hash;
}

static stc_capability *stc_load_capabilities(stc_solver *solver, VALUE capabilities, size_t *out_count) {
  long count = RARRAY_LEN(capabilities);
  stc_capability *caps = calloc((size_t)count, sizeof(stc_capability));
  if (!caps) return NULL;

  for (long i = 0; i < count; i++) {
    VALUE entry = rb_ary_entry(capabilities, i);
    stc_capability *cap = &caps[i];

    VALUE message = stc_hash_get(entry, "message");
    VALUE receiver = stc_hash_get(entry, "receiver");
    VALUE result_id = stc_hash_get(entry, "result");
    VALUE args = stc_hash_get(entry, "args");
    VALUE line = stc_hash_get(entry, "line");

    cap->receiver = stc_type_from_ruby(solver, receiver);
    cap->result = stc_type_var(solver, stc_var_id_from_ruby(result_id), "result");
    strncpy(cap->message, StringValueCStr(message), sizeof(cap->message) - 1);
    cap->line = NIL_P(line) ? 0 : (int32_t)NUM2LONG(line);

    long argc = RARRAY_LEN(args);
    if (argc > 0) {
      cap->args = calloc((size_t)argc, sizeof(stc_type *));
      cap->arg_count = (size_t)argc;
      for (long a = 0; a < argc; a++) {
        cap->args[a] = stc_type_from_ruby(solver, rb_ary_entry(args, a));
      }
    }
  }

  *out_count = (size_t)count;
  return caps;
}

static int stc_load_binding_iter(VALUE key, VALUE value, VALUE arg) {
  stc_solver *solver = (stc_solver *)arg;
  stc_var_id var_id = stc_var_id_from_ruby(key);
  stc_type *type = stc_type_from_ruby(solver, value);
  stc_bind(solver, var_id, type);
  return ST_CONTINUE;
}

static void stc_load_bindings(stc_solver *solver, VALUE bindings) {
  rb_hash_foreach(bindings, stc_load_binding_iter, (VALUE)solver);
}

static VALUE stc_export_bindings(stc_solver *solver) {
  VALUE bindings = rb_hash_new();
  for (size_t i = 0; i < solver->sub_count; i++) {
    stc_substitution *sub = &solver->subs[i];
    stc_type *resolved = stc_dereference(solver, sub->type);
    VALUE key = stc_var_id_to_ruby(sub->var_id);
    rb_hash_aset(bindings, key, stc_type_to_ruby(resolved));
  }
  return bindings;
}

static VALUE stc_solve_graph(VALUE self, VALUE graph) {
  (void)self;
  Check_Type(graph, T_HASH);

  stc_solver *solver = stc_solver_new();
  if (!solver) rb_raise(rb_eNoMemError, "stc_solver_new failed");

  VALUE capabilities = stc_hash_get(graph, "capabilities");
  VALUE bindings = stc_hash_get(graph, "bindings");
  Check_Type(capabilities, T_ARRAY);

  size_t cap_count = 0;
  stc_capability *caps = stc_load_capabilities(solver, capabilities, &cap_count);
  if (!caps) {
    stc_solver_free(solver);
    rb_raise(rb_eNoMemError, "capability allocation failed");
  }

  stc_solver_load_flat(solver, caps, cap_count);
  if (!NIL_P(bindings)) stc_load_bindings(solver, bindings);

  stc_solver_run(solver);

  VALUE result = rb_hash_new();
  rb_hash_aset(result, ID2SYM(rb_intern("bindings")), stc_export_bindings(solver));
  rb_hash_aset(result, ID2SYM(rb_intern("iterations")), INT2NUM(solver->iterations));
  rb_hash_aset(result, ID2SYM(rb_intern("converged")), solver->converged ? Qtrue : Qfalse);

  stc_solver_free(solver);
  return result;
}

static void stc_solver_mark(void *ptr) {
  (void)ptr;
}

static void stc_solver_free_rb(void *ptr) {
  stc_solver_free((stc_solver *)ptr);
}

static size_t stc_solver_memsize(const void *ptr) {
  (void)ptr;
  return sizeof(stc_solver);
}

static const rb_data_type_t stc_solver_type = {
    .wrap_struct_name = "Autotype::Native::Solver",
    .function = {
        .dmark = stc_solver_mark,
        .dfree = stc_solver_free_rb,
        .dsize = stc_solver_memsize,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE stc_solver_alloc(VALUE klass) {
  stc_solver *solver = stc_solver_new();
  if (!solver) rb_raise(rb_eNoMemError, "stc_solver_new failed");
  return TypedData_Wrap_Struct(klass, &stc_solver_type, solver);
}

static VALUE stc_solver_run_rb(VALUE self) {
  stc_solver *solver;
  TypedData_Get_Struct(self, stc_solver, &stc_solver_type, solver);
  int converged = stc_solver_run(solver);
  return INT2NUM(converged ? solver->iterations : -1);
}

static VALUE stc_solver_available(VALUE self) {
  (void)self;
  return Qtrue;
}

void Init_autotype(void) {
  stc_mAutotypeNative = rb_define_module("AutotypeNative");
  stc_cSolver = rb_define_class_under(stc_mAutotypeNative, "Solver", rb_cObject);
  rb_define_alloc_func(stc_cSolver, stc_solver_alloc);
  rb_define_singleton_method(stc_mAutotypeNative, "available?", stc_solver_available, 0);
  rb_define_singleton_method(stc_mAutotypeNative, "solve_graph", stc_solve_graph, 1);
  rb_define_method(stc_cSolver, "run", stc_solver_run_rb, 0);
}
