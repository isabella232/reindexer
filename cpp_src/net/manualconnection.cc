#include "manualconnection.h"
#include <errno.h>

namespace reindexer {
namespace net {

manual_connection::manual_connection(int fd, ev::dynamic_loop &loop, bool enable_stat)
	: sock_(fd), stats_(enable_stat ? new connection_stats_collector : nullptr) {
	attach(loop);
}

manual_connection::~manual_connection() {
	if (sock_.valid()) {
		io_.stop();
		sock_.close();
	}
}

void manual_connection::attach(ev::dynamic_loop &loop) noexcept {
	assert(!attached_);
	io_.set<manual_connection, &manual_connection::io_callback>(this);
	io_.set(loop);
	if (stats_) stats_->attach(loop);
	if (cur_events_) io_.start(sock_.fd(), cur_events_);
	attached_ = true;
}

void manual_connection::detach() noexcept {
	assert(attached_);
	io_.stop();
	io_.reset();
	if (stats_) stats_->detach();
	attached_ = false;
}

void manual_connection::close_conn(int err) {
	state_ = conn_state::init;
	if (sock_.valid()) {
		io_.stop();
		sock_.close();
	}
	if (!r_data_.empty()) {
		on_async_op_done(r_data_, err, ev::READ);
	}
	if (!w_data_.empty()) {
		on_async_op_done(w_data_, err, ev::WRITE);
	}
	if (stats_) stats_->stop();
}

void manual_connection::restart(int fd) {
	assert(!sock_.valid());
	sock_ = fd;
	if (stats_) stats_->restart();
}

int manual_connection::async_connect(string_view addr) noexcept {
	if (state_ == conn_state::connected || state_ == conn_state::connecting) {
		close_conn(k_sock_closed_err);
	}
	assert(w_data_.empty());
	int ret = sock_.connect(addr);
	if (ret == 0) {
		state_ = conn_state::connected;
		return 0;
	} else if (!sock_.would_block(sock_.last_error())) {
		state_ = conn_state::init;
		return -1;
	}
	state_ = conn_state::connecting;
	add_io_events(ev::WRITE);
	return 0;
}

ssize_t manual_connection::write(span<char> wr_buf, transfer_data &transfer, int *err_ptr) {
	if (err_ptr) *err_ptr = 0;
	ssize_t written = -1;
	auto cur_buf = wr_buf.subspan(transfer.transfered_size());
	do {
		written = sock_.send(cur_buf);
		int err = sock_.last_error();

		if (written < 0) {
			if (err == EINTR) {
				continue;
			} else {
				if (err_ptr) *err_ptr = err;
				if (socket::would_block(err)) {
					return 0;
				}
				close_conn(err);
				return -1;
			}
		}
	} while (written < 0);

	transfer.append_transfered(written);

	assert(wr_buf.size() >= transfer.transfered_size());
	auto remaining = wr_buf.size() - transfer.transfered_size();
	if (stats_) stats_->update_write_stats(written, remaining);

	if (remaining == 0) {
		on_async_op_done(w_data_, 0, ev::WRITE);
	}
	return written;
}

ssize_t manual_connection::read(span<char> rd_buf, transfer_data &transfer, int *err_ptr) {
	bool need_read = !transfer.expected_size();
	ssize_t nread = 0;
	ssize_t read_this_time = 0;
	if (err_ptr) *err_ptr = 0;
	auto cur_buf = rd_buf.subspan(transfer.transfered_size());
	while (transfer.transfered_size() < transfer.expected_size() || need_read) {
		nread = sock_.recv(cur_buf);
		int err = sock_.last_error();

		if (nread < 0 && err == EINTR) continue;

		if ((nread < 0 && !socket::would_block(err)) || nread == 0) {
			if (nread == 0) err = k_sock_closed_err;
			if (err_ptr) *err_ptr = err;
			close_conn(err);
			return -1;
		} else if (nread > 0) {
			need_read = false;
			read_this_time += nread;
			transfer.append_transfered(nread);
			if (stats_) stats_->update_read_stats(nread);
			cur_buf = cur_buf.subspan(nread);
		} else {
			if (err_ptr) *err_ptr = err;
			return nread;
		}
	}
	on_async_op_done(r_data_, 0, ev::READ);
	return read_this_time;
}

void manual_connection::add_io_events(int events) noexcept {
	int curEvents = cur_events_;
	cur_events_ |= events;
	if (curEvents != cur_events_) {
		if (curEvents == 0) {
			io_.start(sock_.fd(), cur_events_);
		} else {
			io_.set(cur_events_);
		}
	}
}

void manual_connection::rm_io_events(int events) noexcept {
	int curEvents = cur_events_;
	cur_events_ &= ~events;
	if (curEvents != cur_events_) {
		if (cur_events_ == 0) {
			io_.stop();
		} else {
			io_.set(cur_events_);
		}
	}
}

void manual_connection::io_callback(ev::io &, int revents) {
	if (ev::ERROR & revents) return;

	if (revents & ev::READ) {
		read_cb();
		revents |= ev::WRITE;
	}
	if (revents & ev::WRITE) {
		write_cb();
	}
}

void manual_connection::write_cb() {
	if (state_ == conn_state::connecting) state_ = conn_state::connected;
	if (w_data_.buf.size()) {
		write(w_data_.buf, w_data_.transfer, nullptr);
	} else {
		rm_io_events(ev::WRITE);
	}
}

void manual_connection::read_cb() {
	if (r_data_.buf.size()) {
		read(r_data_.buf, r_data_.transfer, nullptr);
	}
}

}  // namespace net
}  // namespace reindexer
