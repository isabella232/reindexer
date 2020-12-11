#pragma once

#include "coroutine.h"

namespace reindexer {
namespace coroutine {

/// @class Allows to await specified number of coroutines
class wait_group {
public:
	/// Add specified number of coroutines to wait
	void add(size_t cnt) noexcept { wait_cnt_ += cnt; }
	/// Should be called on coroutine's exit
	void done() {
		assert(wait_cnt_);
		if (--wait_cnt_ == 0 && waiter_) {
			resume(waiter_);
		}
	}
	/// Await coroutines
	void wait() {
		waiter_ = current();
		while (wait_cnt_) {
			assert(waiter_);
			suspend();
		}
	}
	/// Get await count
	size_t wait_count() const noexcept { return wait_cnt_; }

private:
	size_t wait_cnt_ = 0;
	routine_t waiter_ = 0;
};

/// @class Allows to call done() method for wait_group on giards destruction
class wait_group_guard {
public:
	wait_group_guard(wait_group& wg) : wg_(wg) {}
	~wait_group_guard() { wg_.done(); }

private:
	wait_group& wg_;
};

}  // namespace coroutine
}  // namespace reindexer
