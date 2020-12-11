#include "coroclientconnection.h"
#include <errno.h>
#include <snappy.h>
#include "core/rdxcontext.h"
#include "coroclientconnection.h"
#include "reindexer_version.h"
#include "tools/serializer.h"

#include <functional>

namespace reindexer {
namespace net {
namespace cproto {

constexpr size_t kMaxRecycledChuncks = 1024;
constexpr size_t kMaxParallelRPCCalls = 512;
constexpr size_t kDeadlineCheckInterval = 1;
constexpr size_t kKeepAliveInterval = 30;
constexpr size_t kUpdatesChannelSize = 128;
constexpr size_t kReadBufReserveSize = 0x1000;

CoroClientConnection::CoroClientConnection(ev::dynamic_loop &loop)
	: now_(0),
	  loop_(loop),
	  rpcCalls_(kMaxParallelRPCCalls),
	  seqNums_(kMaxParallelRPCCalls),
	  updatesCh_(kUpdatesChannelSize),
	  conn_(-1, loop, false) {
	recycledChuncks_.reserve(kMaxRecycledChuncks);
	errSyncCh_.close();
	wg_.add(1);
	loop_.spawn([this] {
		coroutine::wait_group_guard wgg(wg_);
		for (size_t i = 1; i < seqNums_.capacity(); ++i) {
			// seq num == 0 is reserved for login
			seqNums_.push(i);
		}
	});
}

CoroClientConnection::~CoroClientConnection() { Stop(); }

void CoroClientConnection::Start(ConnectData connectData) {
	if (!isRunning_) {
		connectData_ = std::move(connectData);
		if (!updatesCh_.opened()) {
			updatesCh_.reopen();
		}
		if (!wrCh_.opened()) {
			wrCh_.reopen();
		}
		wg_.add(4);
		loop_.spawn([this] {
			coroutine::wait_group_guard wgg(wg_);
			writerRoutine();
		});
		loop_.spawn([this] {
			coroutine::wait_group_guard wgg(wg_);
			deadlineRoutine();
		});
		loop_.spawn([this] {
			coroutine::wait_group_guard wgg(wg_);
			pingerRoutine();
		});
		loop_.spawn([this] {
			coroutine::wait_group_guard wgg(wg_);
			updatesRoutine();
		});

		isRunning_ = true;
	}
}

void CoroClientConnection::Stop() {
	if (isRunning_) {
		terminate_ = true;
		updatesCh_.close();
		wrCh_.close();
		conn_.close_conn(k_sock_closed_err);
		wg_.wait();
		readWg_.wait();
		terminate_ = false;
		isRunning_ = false;
	}
}

Error CoroClientConnection::Status(std::chrono::seconds netTimeout, std::chrono::milliseconds execTimeout, const IRdxCancelContext *ctx) {
	if (loggedIn_) {
		return errOK;
	}
	return call({kCmdPing, netTimeout, execTimeout, ctx}, {}).Status();
}

CoroRPCAnswer CoroClientConnection::call(const CommandParams &opts, const Args &args) {
	if (opts.cancelCtx) {
		switch (opts.cancelCtx->GetCancelType()) {
			case CancelType::Explicit:
				return Error(errCanceled, "Canceled by context");
			case CancelType::Timeout:
				return Error(errTimeout, "Canceled by timeout");
			default:
				break;
		}
	}
	if (terminate_ || !isRunning_) {
		return Error(errLogic, "Client is not running");
	}

	auto deadline = opts.netTimeout.count() ? Now() + opts.netTimeout : seconds(0);
	auto seqp = seqNums_.pop();
	if (!seqp.second) {
		CoroRPCAnswer(Error(errLogic, "Unable to get seq num"));
	}

	// Don't allow to add new requests, while error handling is in progress
	errSyncCh_.pop();

	uint32_t seq = seqp.first;
	auto &call = rpcCalls_[seq % rpcCalls_.size()];
	call.seq = seq;
	call.used = true;
	call.deadline = deadline;
	call.cancelCtx = opts.cancelCtx;
	CoroRPCAnswer ans;
	try {
		wrCh_.push(packRPC(opts.cmd, seq, args, Args{Arg{int64_t(opts.execTimeout.count())}}));
		auto ansp = call.rspCh.pop();
		if (ansp.second) {
			ans = std::move(ansp.first);
		} else {
			ans = CoroRPCAnswer(Error(errLogic, "Response channel is closed"));
		}
	} catch (...) {
		ans = CoroRPCAnswer(Error(errNetwork, "Writing channel is closed"));
	}

	call.used = false;
	seqNums_.push(seq + seqNums_.capacity());
	return ans;
}

CoroClientConnection::MarkedChunk CoroClientConnection::packRPC(CmdCode cmd, uint32_t seq, const Args &args, const Args &ctxArgs) {
	CProtoHeader hdr;
	hdr.len = 0;
	hdr.magic = kCprotoMagic;
	hdr.version = kCprotoVersion;
	hdr.compressed = enableSnappy_;
	hdr.cmd = cmd;
	hdr.seq = seq;

	chunk ch = getChunk();
	WrSerializer ser(std::move(ch));

	ser.Write(string_view(reinterpret_cast<char *>(&hdr), sizeof(hdr)));
	args.Pack(ser);
	ctxArgs.Pack(ser);
	if (hdr.compressed) {
		auto data = ser.Slice().substr(sizeof(hdr));
		std::string compressed;
		snappy::Compress(data.data(), data.length(), &compressed);
		ser.Reset(sizeof(hdr));
		ser.Write(compressed);
	}
	assert(ser.Len() < size_t(std::numeric_limits<int32_t>::max()));
	reinterpret_cast<CProtoHeader *>(ser.Buf())->len = ser.Len() - sizeof(hdr);

	return {seq, ser.DetachChunk()};
}

void CoroClientConnection::appendChunck(std::vector<char> &buf, chunk &&ch) {
	auto oldBufSize = buf.size();
	buf.resize(buf.size() + ch.size());
	memcpy(buf.data() + oldBufSize, ch.data(), ch.size());
	recycleChunk(std::move(ch));
}

Error CoroClientConnection::login(std::vector<char> &buf) {
	assert(conn_.state() != manual_connection::conn_state::connecting);
	if (conn_.state() == manual_connection::conn_state::init) {
		readWg_.wait();
		lastError_ = errOK;
		string port = connectData_.uri.port().length() ? connectData_.uri.port() : string("6534");
		int ret = conn_.async_connect(connectData_.uri.hostname() + ":" + port);
		if (ret < 0) {
			// unable to connect
			return Error(errNetwork, "Connect error");
		}

		string dbName = connectData_.uri.path();
		string userName = connectData_.uri.username();
		string password = connectData_.uri.password();
		if (dbName[0] == '/') dbName = dbName.substr(1);
		enableCompression_ = connectData_.opts.enableCompression;
		Args args = {Arg{p_string(&userName)},
					 Arg{p_string(&password)},
					 Arg{p_string(&dbName)},
					 Arg{connectData_.opts.createDB},
					 Arg{connectData_.opts.hasExpectedClusterID},
					 Arg{connectData_.opts.expectedClusterID},
					 Arg{p_string(REINDEX_VERSION)},
					 Arg{p_string(&connectData_.opts.appName)}};
		constexpr uint32_t seq = 0;	 // login's seq num is always 0
		assert(buf.size() == 0);
		appendChunck(buf, packRPC(kCmdLogin, seq, args, Args{Arg{int64_t(0)}}).data);
		int err = 0;
		auto written = conn_.async_write(buf, err);
		auto toWrite = buf.size();
		buf.clear();
		if (err) {
			// TODO: handle reconnects
			return err > 0 ? Error(errNetwork, "Connection error: %s", strerror(err))
						   : (lastError_.ok() ? Error(errNetwork, "Unable to write login cmd: connection closed") : lastError_);
		}
		assert(written == toWrite);
		(void)written;
		(void)toWrite;

		readWg_.add(1);
		loop_.spawn([this] {
			coroutine::wait_group_guard readWgg(readWg_);
			readerRoutine();
		});
	}
	return errOK;
}

void CoroClientConnection::closeConn(Error err) noexcept {
	errSyncCh_.reopen();
	lastError_ = err;
	conn_.close_conn(k_sock_closed_err);
	handleFatalError(std::move(err));
}

void CoroClientConnection::handleFatalError(Error err) noexcept {
	if (!errSyncCh_.opened()) {
		errSyncCh_.reopen();
	}
	loggedIn_ = false;
	for (auto &c : rpcCalls_) {
		if (c.used && c.rspCh.opened() && !c.rspCh.full()) {
			c.rspCh.push(err);
		}
	}
	if (fatalErrorHandler_) {
		fatalErrorHandler_(err);
	}
	errSyncCh_.close();
}

chunk CoroClientConnection::getChunk() noexcept {
	chunk ch;
	if (recycledChuncks_.size()) {
		ch = std::move(recycledChuncks_.back());
		ch.len_ = 0;
		ch.offset_ = 0;
		recycledChuncks_.pop_back();
	}
	return ch;
}

void CoroClientConnection::recycleChunk(chunk &&ch) noexcept {
	if (recycledChuncks_.size() < kMaxRecycledChuncks) {
		recycledChuncks_.emplace_back(std::move(ch));
	}
}

void CoroClientConnection::writerRoutine() {
	std::vector<char> buf;
	buf.reserve(0x800);

	while (!terminate_) {
		do {
			auto mch = wrCh_.pop();
			if (!mch.second) {
				// channels is closed
				break;
			}
			auto status = login(buf);
			if (!status.ok()) {
				recycleChunk(std::move(mch.first.data));
				handleFatalError(status);
				continue;
			}
			appendChunck(buf, std::move(mch.first.data));
		} while (wrCh_.size());
		int err = 0;
		auto written = conn_.async_write(buf, err);
		if (err) {
			// disconnected
			buf.clear();
			if (lastError_.ok()) {
				handleFatalError(Error(errNetwork, "Write error: %s", err > 0 ? strerror(err) : "Connection closed"));
			}
			continue;
		}
		assert(written == buf.size());
		(void)written;
		buf.clear();
	}
}

void CoroClientConnection::readerRoutine() {
	CProtoHeader hdr;
	std::vector<char> buf;
	buf.reserve(kReadBufReserveSize);
	std::string uncompressed;
	do {
		buf.resize(sizeof(CProtoHeader));
		int err = 0;
		auto read = conn_.async_read(buf, sizeof(CProtoHeader), err);
		if (err) {
			// disconnected
			if (lastError_.ok()) {
				handleFatalError(err > 0 ? Error(errNetwork, "Read error: %s", strerror(err)) : Error(errNetwork, "Connection closed"));
			}
			break;
		}
		assert(read == sizeof(hdr));
		(void)read;
		memcpy(&hdr, buf.data(), sizeof(hdr));

		if (hdr.magic != kCprotoMagic) {
			// disconnect
			closeConn(Error(errNetwork, "Invalid cproto magic=%08x", hdr.magic));
			break;
		}

		if (hdr.version < kCprotoMinCompatVersion) {
			// disconnect
			closeConn(Error(errParams, "Unsupported cproto version %04x. This client expects reindexer server v1.9.8+", int(hdr.version)));
			break;
		}

		buf.resize(hdr.len);
		read = conn_.async_read(buf, size_t(hdr.len), err);
		if (err) {
			// disconnected
			if (lastError_.ok()) {
				handleFatalError(err > 0 ? Error(errNetwork, "Read error: %s", strerror(err)) : Error(errNetwork, "Connection closed"));
			}
			break;
		}
		assert(read == hdr.len);
		(void)read;

		CoroRPCAnswer ans;
		int errCode = 0;
		try {
			Serializer ser(buf.data(), hdr.len);
			if (hdr.compressed) {
				uncompressed.reserve(kReadBufReserveSize);
				if (!snappy::Uncompress(buf.data(), hdr.len, &uncompressed)) {
					throw Error(errParseBin, "Can't decompress data from peer");
				}
				ser = Serializer(uncompressed);
			}

			errCode = ser.GetVarUint();
			string_view errMsg = ser.GetVString();
			if (errCode != errOK) {
				ans.status_ = Error(errCode, errMsg);
			}
			ans.data_ = {ser.Buf() + ser.Pos(), ser.Len() - ser.Pos()};
		} catch (const Error &err) {
			// disconnect
			closeConn(std::move(err));
			break;
		}

		if (hdr.cmd == kCmdUpdates) {
			if (updatesHandler_) {
				ans.EnsureHold(getChunk());
				updatesCh_.push(std::move(ans));
			}
		} else if (hdr.cmd == kCmdLogin) {
			if (ans.Status().ok()) {
				loggedIn_ = true;
			} else {
				// disconnect
				closeConn(ans.Status());
			}
		} else {
			auto &rpcData = rpcCalls_[hdr.seq % rpcCalls_.size()];
			if (!rpcData.used || rpcData.seq != hdr.seq) {
				auto cmdSv = CmdName(hdr.cmd);
				fprintf(stderr, "Unexpected RPC answer seq=%d cmd=%d(%.*s)\n", int(hdr.seq), hdr.cmd, int(cmdSv.size()), cmdSv.data());
				continue;
			}
			assert(rpcData.rspCh.opened());
			if (!rpcData.rspCh.readers()) {
				// In this case read buffer will be invalidated, before coroutine switch
				ans.EnsureHold(getChunk());
			}
			rpcData.rspCh.push(std::move(ans));
		}
	} while (loggedIn_ && !terminate_);
}

void CoroClientConnection::deadlineRoutine() {
	while (!terminate_) {
		loop_.sleep(std::chrono::seconds(kDeadlineCheckInterval));
		now_ += kDeadlineCheckInterval;

		for (auto &c : rpcCalls_) {
			if (!c.used) continue;
			bool expired = (c.deadline.count() && c.deadline.count() <= now_);
			bool canceled = (c.cancelCtx && c.cancelCtx->IsCancelable() && (c.cancelCtx->GetCancelType() == CancelType::Explicit));
			if (expired || canceled) {
				if (c.rspCh.opened()) {
					c.rspCh.push(Error(expired ? errTimeout : errCanceled, expired ? "Request deadline exceeded" : "Canceled"));
				}
			}
		}
	}
}

void CoroClientConnection::pingerRoutine() {
	while (!terminate_) {
		for (size_t i = 0; i < std::chrono::seconds(kKeepAliveInterval).count(); ++i) {
			loop_.sleep(std::chrono::seconds(1));
			// TODO: Look for a better way
			if (terminate_) {
				return;
			}
		}
		if (conn_.state() != manual_connection::conn_state::init) {
			call({kCmdPing, connectData_.opts.keepAliveTimeout, milliseconds(0), nullptr}, {});
		}
	}
}

void CoroClientConnection::updatesRoutine() {
	while (!terminate_) {
		auto ansp = updatesCh_.pop();
		if (!ansp.second) {
			// Channel is closed
			break;
		}
		auto handler = updatesHandler_;
		auto storage = std::move(ansp.first.storage_);
		if (handler) {
			handler(ansp.first);
		}
		recycleChunk(std::move(storage));
	}
}

}  // namespace cproto
}  // namespace net
}  // namespace reindexer
