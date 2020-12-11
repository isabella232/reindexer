﻿#pragma once

#include <string.h>
#include <mutex>
#include "connectinstatscollector.h"
#include "coroutine/coroutine.h"
#include "estl/cbuf.h"
#include "estl/chunk_buf.h"
#include "estl/mutex.h"
#include "net/socket.h"
#include "tools/ssize_t.h"

namespace reindexer {
namespace net {

using reindexer::cbuf;

constexpr int k_sock_closed_err = -1;

class manual_connection {
public:
	using async_cb_t = std::function<void(int err, size_t cnt, span<char> buf)>;

	enum class conn_state { init, connecting, connected };

	manual_connection(int fd, ev::dynamic_loop &loop, bool enable_stat);
	virtual ~manual_connection();

	void close_conn(int err);
	void attach(ev::dynamic_loop &loop) noexcept;
	void detach() noexcept;
	void restart(int fd);

	template <typename buf_t>
	void async_read(buf_t &data, size_t cnt, async_cb_t cb) {
		async_read_impl(data, cnt, std::move(cb));
	}
	template <typename buf_t>
	size_t async_read(buf_t &data, size_t cnt, int &err) noexcept {
		auto co_id = coroutine::current();
		return async_read_impl<buf_t, suspend_switch_policy>(data, cnt, [&err, co_id](int _err, size_t /*cnt*/, span<char> /*buf*/) {
			err = _err;
			coroutine::resume(co_id);
		});
	}
	template <typename buf_t>
	void async_read_some(buf_t &data, async_cb_t cb) {
		async_read_some_impl(data, std::move(cb));
	}
	template <typename buf_t>
	size_t async_read_some(buf_t &data, int &err) noexcept {
		auto co_id = coroutine::current();
		return async_read_some_impl<buf_t, suspend_switch_policy>(data, [&err, co_id](int _err, size_t /*cnt*/, span<char> /*buf*/) {
			err = _err;
			coroutine::resume(co_id);
		});
	}
	template <typename buf_t>
	void async_write(buf_t &data, async_cb_t cb) {
		async_write_impl(data, std::move(cb));
	}
	template <typename buf_t>
	size_t async_write(buf_t &data, int &err) noexcept {
		auto co_id = coroutine::current();
		return async_write_impl<buf_t, suspend_switch_policy>(data, [&err, co_id](int _err, size_t /*cnt*/, span<char> /*buf*/) {
			err = _err;
			coroutine::resume(co_id);
		});
	}
	int async_connect(string_view addr) noexcept;
	conn_state state() const noexcept { return state_; }

private:
	class transfer_data {
	public:
		void set_expected(size_t expected) {
			expected_size_ = expected;
			transfered_size_ = 0;
		}
		void append_transfered(size_t transfered) { transfered_size_ += transfered; }
		size_t expected_size() const { return expected_size_; }
		size_t transfered_size() const { return transfered_size_; }

	private:
		size_t expected_size_ = 0;
		size_t transfered_size_ = 0;
	};

	struct async_data {
		bool empty() { return cb == nullptr; }
		void set_cb(span<char> _buf, async_cb_t _cb) {
			assert(!cb);
			cb = std::move(_cb);
			buf = _buf;
		}
		void reset() {
			cb = nullptr;
			buf = span<char>();
		}

		async_cb_t cb = nullptr;
		transfer_data transfer;
		span<char> buf;
	};

	struct empty_switch_policy {
		void operator()(async_data & /*data*/) {}
	};
	struct suspend_switch_policy {
		void operator()(async_data &data) {
			while (!data.empty()) {
				coroutine::suspend();
			}
		}
	};

	template <typename buf_t, typename switch_policy_t = empty_switch_policy>
	size_t async_read_impl(buf_t &data, size_t cnt, async_cb_t cb) {
		assert(r_data_.empty());
		assert(data.size() >= cnt);
		auto &transfer = r_data_.transfer;
		transfer.set_expected(cnt);
		int int_err = 0;
		auto data_span = span<char>(data.data(), cnt);
		if (state_ != conn_state::connecting) {
			auto nread = read(data_span, transfer, &int_err);
			if (!nread) {
				return 0;
			}
		}

		if ((!int_err && transfer.transfered_size() < transfer.expected_size()) || sock_.would_block(int_err)) {
			r_data_.set_cb(data_span, std::move(cb));
			add_io_events(ev::READ);
			switch_policy_t swtch;
			swtch(r_data_);
		} else {
			cb(int_err, transfer.transfered_size(), span<char>(data.data(), data.size()));
		}
		return transfer.transfered_size();
	}

	template <typename buf_t, typename switch_policy_t = empty_switch_policy>
	size_t async_read_some_impl(buf_t &data, async_cb_t cb) {
		assert(r_data_.empty());
		assert(data.size());
		auto &transfer = r_data_.transfer;
		transfer.set_expected(0);
		if (state_ != conn_state::connecting) {
			int int_err = 0;
			auto data_span = span<char>(data.data(), data.size());
			auto nread = read(data_span, transfer, &int_err);
			if (nread >= 0 || !sock_.would_block(int_err)) {
				cb(int_err, transfer.transfered_size(), data);
				return transfer.transfered_size();
			}
		}

		r_data_.set_cb(data, std::move(cb));
		add_io_events(ev::READ);
		switch_policy_t swtch;
		swtch(r_data_);
		return r_data_.transfer.transfered_size();
	}

	template <typename buf_t, typename switch_policy_t = empty_switch_policy>
	size_t async_write_impl(buf_t &data, async_cb_t cb) {
		assert(w_data_.empty());
		auto &transfer = w_data_.transfer;
		transfer.set_expected(data.size());
		int int_err = 0;
		if (data.size()) {
			auto data_span = span<char>(data.data(), data.size());
			if (state_ != conn_state::connecting) {
				auto nwrite = write(data_span, transfer, &int_err);
				if (!nwrite) {	// TODO: check this case
					cb(0, 0, data);
					return 0;
				}
			}
			if ((!int_err && transfer.transfered_size() < transfer.expected_size()) || sock_.would_block(int_err)) {
				w_data_.set_cb(data_span, std::move(cb));
				add_io_events(ev::WRITE);
				switch_policy_t swtch;
				swtch(w_data_);
			} else {
				cb(int_err, transfer.transfered_size(), data);
			}
		} else {
			cb(int_err, transfer.transfered_size(), data);
		}
		return transfer.transfered_size();
	}

	void on_async_op_done(async_data &data, int err, int op) {
		rm_io_events(op);
		if (!data.empty()) {
			auto cb = std::move(data.cb);
			auto buf = data.buf;
			auto transfered = data.transfer.transfered_size();
			data.reset();
			cb(err, transfered, buf);
		}
	}
	ssize_t write(span<char>, transfer_data &transfer, int *err_ptr);
	ssize_t read(span<char>, transfer_data &transfer, int *err_ptr);
	void add_io_events(int events) noexcept;
	void rm_io_events(int events) noexcept;
	void io_callback(ev::io &watcher, int revents);
	void write_cb();
	void read_cb();

	ev::io io_;
	socket sock_;
	conn_state state_ = conn_state::init;
	bool attached_ = false;
	int cur_events_ = 0;

	async_data r_data_;
	async_data w_data_;

	std::unique_ptr<connection_stats_collector> stats_;
};

}  // namespace net
}  // namespace reindexer
