#include <r_core.h>
#include "minunit.h"

bool test_r_anal_class_get_all(void) {
	RCore *core = r_core_new ();

	r_anal_class_create (core->anal, "radare2");
	r_anal_class_create (core->anal, "is");
	r_anal_class_create (core->anal, "cool");

	RBufVector *v = r_anal_class_get_all (core->anal);
	mu_assert_eq_fmt (r_pvector_len (&v->v), 3UL, "vector len", "%lu");
	mu_assert_streq ((const char *)r_pvector_at (&v->v, 0), "radare2", "class 0");
	mu_assert_streq ((const char *)r_pvector_at (&v->v, 1), "is", "class 1");
	mu_assert_streq ((const char *)r_pvector_at (&v->v, 2), "cool", "class 2");

	r_buf_vector_free (v);

	r_core_free (core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_r_anal_class_get_all);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
