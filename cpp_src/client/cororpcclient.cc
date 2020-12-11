#include "client/cororpcclient.h"
#include <stdio.h>
#include <functional>
#include "client/itemimpl.h"
#include "core/namespacedef.h"
#include "gason/gason.h"
#include "tools/errors.h"
#include "tools/logger.h"
#include "vendor/gason/gason.h"

using std::string;
using std::vector;

namespace reindexer {
namespace client {

using reindexer::net::cproto::CoroRPCAnswer;

constexpr size_t kSubscriptionCheckInterval = 5;

CoroRPCClient::CoroRPCClient(ev::dynamic_loop& loop, const ReindexerConfig& config) : config_(config), conn_(loop), loop_(loop) {
	if (config_.ConnectTimeout > config_.RequestTimeout) {
		config_.RequestTimeout = config_.ConnectTimeout;
	}
	conn_.SetFatalErrorHandler([this](Error err) { onConnFatalError(std::move(err)); });
}

CoroRPCClient::~CoroRPCClient() { Stop(); }

Error CoroRPCClient::Connect(const string& dsn, const client::ConnectOpts& opts) {
	if (conn_.IsRunning()) {
		return Error(errLogic, "Client is already started");
	}

	cproto::CoroClientConnection::ConnectData connectData;
	if (!connectData.uri.parse(dsn)) {
		return Error(errParams, "%s is not valid uri", dsn);
	}
	if (connectData.uri.scheme() != "cproto") {
		return Error(errParams, "Scheme must be cproto");
	}
	connectData.opts = cproto::CoroClientConnection::Options(config_.ConnectTimeout, config_.RequestTimeout, opts.IsCreateDBIfMissing(),
															 opts.HasExpectedClusterID(), opts.ExpectedClusterID(),
															 config_.ReconnectAttempts, config_.EnableCompression, config_.AppName);
	conn_.Start(std::move(connectData));
	startResubRoutine();
	return errOK;
}

Error CoroRPCClient::Stop() {
	terminate_ = true;
	conn_.Stop();
	resubWg_.wait();
	terminate_ = false;
	return errOK;
}

Error CoroRPCClient::AddNamespace(const NamespaceDef& nsDef, const InternalRdxContext& ctx) {
	WrSerializer ser;
	nsDef.GetJSON(ser);
	auto status = conn_.Call(mkCommand(cproto::kCmdOpenNamespace, &ctx), ser.Slice()).Status();

	if (!status.ok()) return status;

	namespaces_.emplace(nsDef.name, Namespace::Ptr(new Namespace(nsDef.name)));
	return errOK;
}

Error CoroRPCClient::OpenNamespace(string_view nsName, const InternalRdxContext& ctx, const StorageOpts& sopts) {
	NamespaceDef nsDef(string(nsName), sopts);
	return AddNamespace(nsDef, ctx);
}

Error CoroRPCClient::CloseNamespace(string_view nsName, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdCloseNamespace, &ctx), nsName).Status();
}

Error CoroRPCClient::DropNamespace(string_view nsName, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdDropNamespace, &ctx), nsName).Status();
}

Error CoroRPCClient::TruncateNamespace(string_view nsName, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdTruncateNamespace, &ctx), nsName).Status();
}

Error CoroRPCClient::RenameNamespace(string_view srcNsName, const std::string& dstNsName, const InternalRdxContext& ctx) {
	auto status = conn_.Call(mkCommand(cproto::kCmdRenameNamespace, &ctx), srcNsName, dstNsName).Status();

	if (!status.ok()) return status;

	if (srcNsName != dstNsName) {
		auto namespacePtr = namespaces_.find(srcNsName);
		auto namespacePtrDst = namespaces_.find(dstNsName);
		if (namespacePtr != namespaces_.end()) {
			if (namespacePtrDst == namespaces_.end()) {
				namespaces_.emplace(dstNsName, namespacePtr->second);
			} else {
				namespacePtrDst->second = namespacePtr->second;
			}
			namespaces_.erase(namespacePtr);
		} else {
			namespaces_.erase(namespacePtrDst);
		}
	}
	return errOK;
}

Error CoroRPCClient::Insert(string_view nsName, Item& item, const InternalRdxContext& ctx) {
	return modifyItem(nsName, item, ModeInsert, config_.RequestTimeout, ctx);
}

Error CoroRPCClient::Update(string_view nsName, Item& item, const InternalRdxContext& ctx) {
	return modifyItem(nsName, item, ModeUpdate, config_.RequestTimeout, ctx);
}

Error CoroRPCClient::Upsert(string_view nsName, Item& item, const InternalRdxContext& ctx) {
	return modifyItem(nsName, item, ModeUpsert, config_.RequestTimeout, ctx);
}

Error CoroRPCClient::Delete(string_view nsName, Item& item, const InternalRdxContext& ctx) {
	return modifyItem(nsName, item, ModeDelete, config_.RequestTimeout, ctx);
}

Error CoroRPCClient::modifyItem(string_view nsName, Item& item, int mode, seconds netTimeout, const InternalRdxContext& ctx) {
	WrSerializer ser;
	if (item.impl_->GetPrecepts().size()) {
		ser.PutVarUint(item.impl_->GetPrecepts().size());
		for (auto& p : item.impl_->GetPrecepts()) {
			ser.PutVString(p);
		}
	}

	bool withNetTimeout = (netTimeout.count() > 0);
	for (int tryCount = 0;; tryCount++) {
		auto netDeadline = conn_.Now() + netTimeout;
		auto ret = conn_.Call(mkCommand(cproto::kCmdModifyItem, netTimeout, &ctx), nsName, int(FormatCJson), item.GetCJSON(), mode,
							  ser.Slice(), item.GetStateToken(), 0);
		if (ret.Status().ok()) {
			try {
				auto args = ret.GetArgs(2);
				return CoroQueryResults(&conn_, {getNamespace(nsName)}, p_string(args[0]), int(args[1]), 0, config_.FetchAmount,
										config_.RequestTimeout)
					.Status();
			} catch (const Error& err) {
				return err;
			}
		} else {
			if (ret.Status().code() != errStateInvalidated || tryCount > 2) return ret.Status();
			if (withNetTimeout) {
				netTimeout = netDeadline - conn_.Now();
			}
			CoroQueryResults qr;
			InternalRdxContext ctxCompl = ctx.WithCompletion(nullptr);
			auto ret = selectImpl(Query(string(nsName)).Limit(0), qr, netTimeout, ctxCompl);
			if (ret.code() == errTimeout) {
				return Error(errTimeout, "Request timeout");
			}
			if (withNetTimeout) {
				netTimeout = netDeadline - conn_.Now();
			}
			auto newItem = NewItem(nsName);
			char* endp = nullptr;
			Error err = newItem.FromJSON(item.impl_->GetJSON(), &endp);
			if (!err.ok()) return err;

			item = std::move(newItem);
		}
	}
}

Error CoroRPCClient::subscribeImpl(bool subscribe) {
	Error err;
	if (subscribe) {
		UpdatesFilters filter = observers_.GetMergedFilter();
		WrSerializer ser;
		filter.GetJSON(ser);
		err = conn_.Call(mkCommand(cproto::kCmdSubscribeUpdates), 1, ser.Slice()).Status();
		if (err.ok()) {
			conn_.SetUpdatesHandler([this](const CoroRPCAnswer& ans) { onUpdates(ans); });
			subscribed_ = true;
		}
	} else {
		err = conn_.Call(mkCommand(cproto::kCmdSubscribeUpdates), 0).Status();
		if (err.ok()) {
			subscribed_ = false;
		}
	}
	return err;
}

Item CoroRPCClient::NewItem(string_view nsName) {
	try {
		auto ns = getNamespace(nsName);
		return ns->NewItem();
	} catch (const Error& err) {
		return Item(err);
	}
}

Error CoroRPCClient::GetMeta(string_view nsName, const string& key, string& data, const InternalRdxContext& ctx) {
	try {
		auto ret = conn_.Call(mkCommand(cproto::kCmdGetMeta, &ctx), nsName, key);
		if (ret.Status().ok()) {
			data = ret.GetArgs(1)[0].As<string>();
		}
		return ret.Status();
	} catch (const Error& err) {
		return err;
	}
}

Error CoroRPCClient::PutMeta(string_view nsName, const string& key, const string_view& data, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdPutMeta, &ctx), nsName, key, data).Status();
}

Error CoroRPCClient::EnumMeta(string_view nsName, vector<string>& keys, const InternalRdxContext& ctx) {
	try {
		auto ret = conn_.Call(mkCommand(cproto::kCmdEnumMeta, &ctx), nsName);
		if (ret.Status().ok()) {
			auto args = ret.GetArgs();
			keys.clear();
			keys.reserve(args.size());
			for (auto& k : args) {
				keys.push_back(k.As<string>());
			}
		}
		return ret.Status();
	} catch (const Error& err) {
		return err;
	}
}

Error CoroRPCClient::Delete(const Query& query, CoroQueryResults& result, const InternalRdxContext& ctx) {
	WrSerializer ser;
	query.Serialize(ser);

	NSArray nsArray;
	query.WalkNested(true, true, [this, &nsArray](const Query& q) { nsArray.push_back(getNamespace(q._namespace)); });

	result = CoroQueryResults(&conn_, std::move(nsArray), 0, config_.FetchAmount, config_.RequestTimeout);

	auto ret = conn_.Call(mkCommand(cproto::kCmdDeleteQuery, &ctx), ser.Slice(), kResultsWithItemID);
	try {
		if (ret.Status().ok()) {
			auto args = ret.GetArgs(2);
			result.Bind(p_string(args[0]), int(args[1]));
		}
	} catch (const Error& err) {
		return err;
	}
	return ret.Status();
}

Error CoroRPCClient::Update(const Query& query, CoroQueryResults& result, const InternalRdxContext& ctx) {
	WrSerializer ser;
	query.Serialize(ser);

	NSArray nsArray;
	query.WalkNested(true, true, [this, &nsArray](const Query& q) { nsArray.push_back(getNamespace(q._namespace)); });

	result = CoroQueryResults(&conn_, std::move(nsArray), 0, config_.FetchAmount, config_.RequestTimeout);

	auto ret =
		conn_.Call(mkCommand(cproto::kCmdUpdateQuery, &ctx), ser.Slice(), kResultsWithItemID | kResultsWithPayloadTypes | kResultsCJson);
	try {
		if (ret.Status().ok()) {
			auto args = ret.GetArgs(2);
			result.Bind(p_string(args[0]), int(args[1]));
		}
	} catch (const Error& err) {
		return err;
	}
	return ret.Status();
}

void vec2pack(const h_vector<int32_t, 4>& vec, WrSerializer& ser) {
	// Get array of payload Type Versions

	ser.PutVarUint(vec.size());
	for (auto v : vec) ser.PutVarUint(v);
	return;
}

Error CoroRPCClient::selectImpl(string_view query, CoroQueryResults& result, seconds netTimeout, const InternalRdxContext& ctx) {
	int flags = result.fetchFlags_ ? (result.fetchFlags_ & ~kResultsFormatMask) | kResultsJson : kResultsJson;

	WrSerializer pser;
	h_vector<int32_t, 4> vers;
	vec2pack(vers, pser);

	result = CoroQueryResults(&conn_, {}, result.fetchFlags_, config_.FetchAmount, config_.RequestTimeout);

	auto ret = conn_.Call(mkCommand(cproto::kCmdSelectSQL, netTimeout, &ctx), query, flags, config_.FetchAmount, pser.Slice());
	try {
		if (ret.Status().ok()) {
			auto args = ret.GetArgs(2);
			result.Bind(p_string(args[0]), int(args[1]));
		}
	} catch (const Error& err) {
		return err;
	}
	return ret.Status();
}

Error CoroRPCClient::selectImpl(const Query& query, CoroQueryResults& result, seconds netTimeout, const InternalRdxContext& ctx) {
	WrSerializer qser, pser;
	int flags = result.fetchFlags_ ? result.fetchFlags_ : (kResultsWithPayloadTypes | kResultsCJson);
	bool hasJoins = !query.joinQueries_.empty();
	if (!hasJoins) {
		for (auto& mq : query.mergeQueries_) {
			if (!mq.joinQueries_.empty()) {
				hasJoins = true;
				break;
			}
		}
	}
	if (hasJoins) {
		flags &= ~kResultsFormatMask;
		flags |= kResultsJson;
	}
	NSArray nsArray;
	query.Serialize(qser);
	query.WalkNested(true, true, [this, &nsArray](const Query& q) { nsArray.push_back(getNamespace(q._namespace)); });
	h_vector<int32_t, 4> vers;
	for (auto& ns : nsArray) {
		vers.push_back(ns->tagsMatcher_.version() ^ ns->tagsMatcher_.stateToken());
	}
	vec2pack(vers, pser);

	result = CoroQueryResults(&conn_, std::move(nsArray), result.fetchFlags_, config_.FetchAmount, config_.RequestTimeout);

	auto ret = conn_.Call(mkCommand(cproto::kCmdSelect, netTimeout, &ctx), qser.Slice(), flags, config_.FetchAmount, pser.Slice());
	try {
		if (ret.Status().ok()) {
			auto args = ret.GetArgs(2);
			result.Bind(p_string(args[0]), int(args[1]));
		}
	} catch (const Error& err) {
		return err;
	}
	return ret.Status();
}

Error CoroRPCClient::Commit(string_view nsName) { return conn_.Call(mkCommand(cproto::kCmdCommit), nsName).Status(); }

Error CoroRPCClient::AddIndex(string_view nsName, const IndexDef& iDef, const InternalRdxContext& ctx) {
	WrSerializer ser;
	iDef.GetJSON(ser);
	return conn_.Call(mkCommand(cproto::kCmdAddIndex, &ctx), nsName, ser.Slice()).Status();
}

Error CoroRPCClient::UpdateIndex(string_view nsName, const IndexDef& iDef, const InternalRdxContext& ctx) {
	WrSerializer ser;
	iDef.GetJSON(ser);
	return conn_.Call(mkCommand(cproto::kCmdUpdateIndex, &ctx), nsName, ser.Slice()).Status();
}

Error CoroRPCClient::DropIndex(string_view nsName, const IndexDef& idx, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdDropIndex, &ctx), nsName, idx.name_).Status();
}

Error CoroRPCClient::SetSchema(string_view nsName, string_view schema, const InternalRdxContext& ctx) {
	return conn_.Call(mkCommand(cproto::kCmdSetSchema, &ctx), nsName, schema).Status();
}

Error CoroRPCClient::EnumNamespaces(vector<NamespaceDef>& defs, EnumNamespacesOpts opts, const InternalRdxContext& ctx) {
	try {
		auto ret = conn_.Call(mkCommand(cproto::kCmdEnumNamespaces, &ctx), int(opts.options_), p_string(&opts.filter_));
		if (ret.Status().ok()) {
			gason::JsonParser parser;
			auto json = ret.GetArgs(1)[0].As<string>();
			auto root = parser.Parse(giftStr(json));

			for (auto& nselem : root["items"]) {
				NamespaceDef def;
				def.FromJSON(nselem);
				defs.emplace_back(std::move(def));
			}
		}
		return ret.Status();
	} catch (const Error& err) {
		return err;
	} catch (const gason::Exception& err) {
		return Error(errParseJson, "EnumNamespaces: %s", err.what());
	}
}

Error CoroRPCClient::EnumDatabases(vector<string>& dbList, const InternalRdxContext& ctx) {
	try {
		auto ret = conn_.Call(mkCommand(cproto::kCmdEnumDatabases, &ctx), 0);
		if (ret.Status().ok()) {
			gason::JsonParser parser;
			auto json = ret.GetArgs(1)[0].As<string>();
			auto root = parser.Parse(giftStr(json));
			for (auto& elem : root["databases"]) {
				dbList.emplace_back(elem.As<string>());
			}
		}
		return ret.Status();
	} catch (const Error& err) {
		return err;
	} catch (const gason::Exception& err) {
		return Error(errParseJson, "EnumDatabases: %s", err.what());
	}
}

Error CoroRPCClient::SubscribeUpdates(IUpdatesObserver* observer, const UpdatesFilters& filters, SubscriptionOpts opts) {
	observers_.Add(observer, filters, opts);
	return subscribeImpl(true);
}

Error CoroRPCClient::UnsubscribeUpdates(IUpdatesObserver* observer) {
	observers_.Delete(observer);
	return subscribeImpl(!observers_.Empty());
}

Error CoroRPCClient::GetSqlSuggestions(string_view query, int pos, std::vector<std::string>& suggests) {
	try {
		auto ret = conn_.Call(mkCommand(cproto::kCmdGetSQLSuggestions), query, pos);
		if (ret.Status().ok()) {
			auto rargs = ret.GetArgs();
			suggests.clear();
			suggests.reserve(rargs.size());

			for (auto& rarg : rargs) suggests.push_back(rarg.As<string>());
		}
		return ret.Status();
	} catch (const Error& err) {
		return err;
	}
}

Error CoroRPCClient::Status(const InternalRdxContext& ctx) {
	return conn_.Status(config_.RequestTimeout, ctx.execTimeout(), ctx.getCancelCtx());
}

Namespace* CoroRPCClient::getNamespace(string_view nsName) {
	auto nsIt = namespaces_.find(nsName);
	if (nsIt == namespaces_.end()) {
		string nsNames(nsName);
		auto nsPtr = Namespace::Ptr(new Namespace(nsNames));
		nsIt = namespaces_.emplace(std::move(nsNames), std::move(nsPtr)).first;
	}
	return nsIt->second.get();
}

cproto::CommandParams CoroRPCClient::mkCommand(cproto::CmdCode cmd, const InternalRdxContext* ctx) const noexcept {
	return mkCommand(cmd, config_.RequestTimeout, ctx);
}

cproto::CommandParams CoroRPCClient::mkCommand(cproto::CmdCode cmd, std::chrono::seconds reqTimeout,
											   const InternalRdxContext* ctx) noexcept {
	if (ctx) {
		return {cmd, reqTimeout, ctx->execTimeout(), ctx->getCancelCtx()};
	}
	return {cmd, reqTimeout, std::chrono::milliseconds(0), nullptr};
}

void CoroRPCClient::onUpdates(const cproto::CoroRPCAnswer& ans) {
	if (!ans.Status().ok()) {
		observers_.OnConnectionState(ans.Status());
		return;
	}

	cproto::Args args;
	try {
		args = ans.GetArgs(3);
	} catch (const Error& err) {
		logPrintf(LogError, "[RPCClient] Parsing updates error: %s", err.what());
		return;
	}

	lsn_t lsn{int64_t(args[0])};
	string_view nsName(args[1]);
	string_view pwalRec(args[2]);
	lsn_t originLSN;
	if (args.size() >= 4) originLSN = lsn_t(args[3].As<int64_t>());
	WALRecord wrec(pwalRec);

	if (wrec.type == WalItemModify) {
		// Special process for Item Modify
		auto ns = getNamespace(nsName);

		// Check if cjson with bundled tagsMatcher
		bool bundledTagsMatcher = wrec.itemModify.itemCJson.length() > 0 && wrec.itemModify.itemCJson[0] == TAG_END;

		auto tmVersion = ns->tagsMatcher_.version();

		if (tmVersion < wrec.itemModify.tmVersion && !bundledTagsMatcher) {
			// If tagsMatcher has been updated but there is no bundled tagsMatcher in cjson
			// then we need to ask server to send tagsMatcher.

			InternalRdxContext ctx(nullptr);
			CoroQueryResults qr;
			auto err = Select(Query(string(nsName)).Limit(0), qr, ctx);
			if (!err.ok()) return;
		} else {
			// We have bundled tagsMatcher
			if (bundledTagsMatcher) {
				try {
					// printf("%s bundled tm %d to %d\n", ns->name_.c_str(), ns->tagsMatcher_.version(), wrec.itemModify.tmVersion);
					Serializer rdser(wrec.itemModify.itemCJson);
					rdser.GetVarUint();
					uint32_t tmOffset = rdser.GetUInt32();
					// read tags matcher update
					rdser.SetPos(tmOffset);
					ns = getNamespace(nsName);
					ns->tagsMatcher_ = TagsMatcher();
					ns->tagsMatcher_.deserialize(rdser, wrec.itemModify.tmVersion, ns->tagsMatcher_.stateToken());
				} catch (Error&) {
					assert(false);
					return;
				}
			}
		}
	}

	observers_.OnWALUpdate(LSNPair(lsn, originLSN), nsName, wrec);
}

void CoroRPCClient::startResubRoutine() {
	if (!resubWg_.wait_count()) {
		resubWg_.add(1);
		loop_.spawn([this] {
			coroutine::wait_group_guard wgg(resubWg_);
			resubRoutine();
		});
	}
}

void CoroRPCClient::resubRoutine() {
	while (!terminate_) {
		for (std::chrono::seconds::rep i = 0; i < std::chrono::seconds(kSubscriptionCheckInterval).count(); ++i) {
			loop_.sleep(std::chrono::seconds(1));
			// TODO Look for a better way
			if (terminate_) {
				return;
			}
		}
		if (subscribed_) {
			if (observers_.Empty()) {
				subscribeImpl(false);
			}
		} else {
			if (!observers_.Empty()) {
				subscribeImpl(true);
			}
		}
	}
}

CoroTransaction CoroRPCClient::NewTransaction(string_view nsName, const InternalRdxContext& ctx) {
	auto ret = conn_.Call(mkCommand(cproto::kCmdStartTransaction, &ctx), nsName);
	auto err = ret.Status();
	if (err.ok()) {
		try {
			auto args = ret.GetArgs(1);
			return CoroTransaction(this, &conn_, int64_t(args[0]), config_.RequestTimeout, ctx.execTimeout(),
								   std::string(nsName.data(), nsName.size()));
		} catch (Error& e) {
			err = std::move(e);
		}
	}
	return CoroTransaction(std::move(err));
}

Error CoroRPCClient::CommitTransaction(CoroTransaction& tr, const InternalRdxContext& ctx) {
	if (tr.conn_) {
		auto ret = tr.conn_->Call(mkCommand(cproto::kCmdCommitTx, &ctx), tr.txId_).Status();
		tr.clear();
		return ret;
	}
	return Error(errLogic, "connection is nullptr");
}
Error CoroRPCClient::RollBackTransaction(CoroTransaction& tr, const InternalRdxContext& ctx) {
	if (tr.conn_) {
		auto ret = tr.conn_->Call(mkCommand(cproto::kCmdRollbackTx, &ctx), tr.txId_).Status();
		tr.clear();
		return ret;
	}
	return Error(errLogic, "connection is nullptr");
}

}  // namespace client
}  // namespace reindexer
