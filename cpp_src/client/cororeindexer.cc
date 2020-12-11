#include "client/cororeindexer.h"
#include "client/cororpcclient.h"
#include "tools/logger.h"

namespace reindexer {
namespace client {

CoroReindexer::CoroReindexer(dynamic_loop& loop, const ReindexerConfig& config)
	: impl_(new CoroRPCClient(loop, config)), owner_(true), ctx_() {}
CoroReindexer::~CoroReindexer() {
	if (owner_) {
		delete impl_;
	}
}
CoroReindexer::CoroReindexer(CoroReindexer&& rdx) noexcept : impl_(rdx.impl_), owner_(rdx.owner_), ctx_(rdx.ctx_) { rdx.owner_ = false; }
CoroReindexer& CoroReindexer::operator=(CoroReindexer&& rdx) noexcept {
	if (this != &rdx) {
		impl_ = rdx.impl_;
		owner_ = rdx.owner_;
		ctx_ = rdx.ctx_;
		rdx.owner_ = false;
	}
	return *this;
}

Error CoroReindexer::Connect(const string& dsn, const client::ConnectOpts& opts) { return impl_->Connect(dsn, opts); }
Error CoroReindexer::Stop() { return impl_->Stop(); }
Error CoroReindexer::AddNamespace(const NamespaceDef& nsDef) { return impl_->AddNamespace(nsDef, ctx_); }
Error CoroReindexer::OpenNamespace(string_view nsName, const StorageOpts& storage) { return impl_->OpenNamespace(nsName, ctx_, storage); }
Error CoroReindexer::DropNamespace(string_view nsName) { return impl_->DropNamespace(nsName, ctx_); }
Error CoroReindexer::CloseNamespace(string_view nsName) { return impl_->CloseNamespace(nsName, ctx_); }
Error CoroReindexer::TruncateNamespace(string_view nsName) { return impl_->TruncateNamespace(nsName, ctx_); }
Error CoroReindexer::RenameNamespace(string_view srcNsName, const std::string& dstNsName) {
	return impl_->RenameNamespace(srcNsName, dstNsName, ctx_);
}
Error CoroReindexer::Insert(string_view nsName, Item& item) { return impl_->Insert(nsName, item, ctx_); }
Error CoroReindexer::Update(string_view nsName, Item& item) { return impl_->Update(nsName, item, ctx_); }
Error CoroReindexer::Update(const Query& q, CoroQueryResults& result) { return impl_->Update(q, result, ctx_); }
Error CoroReindexer::Upsert(string_view nsName, Item& item) { return impl_->Upsert(nsName, item, ctx_); }
Error CoroReindexer::Delete(string_view nsName, Item& item) { return impl_->Delete(nsName, item, ctx_); }
Item CoroReindexer::NewItem(string_view nsName) { return impl_->NewItem(nsName); }
Error CoroReindexer::GetMeta(string_view nsName, const string& key, string& data) { return impl_->GetMeta(nsName, key, data, ctx_); }
Error CoroReindexer::PutMeta(string_view nsName, const string& key, const string_view& data) {
	return impl_->PutMeta(nsName, key, data, ctx_);
}
Error CoroReindexer::EnumMeta(string_view nsName, vector<string>& keys) { return impl_->EnumMeta(nsName, keys, ctx_); }
Error CoroReindexer::Delete(const Query& q, CoroQueryResults& result) { return impl_->Delete(q, result, ctx_); }
Error CoroReindexer::Select(string_view query, CoroQueryResults& result) { return impl_->Select(query, result, ctx_); }
Error CoroReindexer::Select(const Query& q, CoroQueryResults& result) { return impl_->Select(q, result, ctx_); }
Error CoroReindexer::Commit(string_view nsName) { return impl_->Commit(nsName); }
Error CoroReindexer::AddIndex(string_view nsName, const IndexDef& idx) { return impl_->AddIndex(nsName, idx, ctx_); }
Error CoroReindexer::UpdateIndex(string_view nsName, const IndexDef& idx) { return impl_->UpdateIndex(nsName, idx, ctx_); }
Error CoroReindexer::DropIndex(string_view nsName, const IndexDef& index) { return impl_->DropIndex(nsName, index, ctx_); }
Error CoroReindexer::SetSchema(string_view nsName, string_view schema) { return impl_->SetSchema(nsName, schema, ctx_); }
Error CoroReindexer::EnumNamespaces(vector<NamespaceDef>& defs, EnumNamespacesOpts opts) { return impl_->EnumNamespaces(defs, opts, ctx_); }
Error CoroReindexer::EnumDatabases(vector<string>& dbList) { return impl_->EnumDatabases(dbList, ctx_); }
Error CoroReindexer::SubscribeUpdates(IUpdatesObserver* observer, const UpdatesFilters& filters, SubscriptionOpts opts) {
	return impl_->SubscribeUpdates(observer, filters, opts);
}
Error CoroReindexer::UnsubscribeUpdates(IUpdatesObserver* observer) { return impl_->UnsubscribeUpdates(observer); }
Error CoroReindexer::GetSqlSuggestions(const string_view sqlQuery, int pos, vector<string>& suggests) {
	return impl_->GetSqlSuggestions(sqlQuery, pos, suggests);
}
Error CoroReindexer::Status() { return impl_->Status(ctx_); }

CoroTransaction CoroReindexer::NewTransaction(string_view nsName) { return impl_->NewTransaction(nsName, ctx_); }
Error CoroReindexer::CommitTransaction(CoroTransaction& tr) { return impl_->CommitTransaction(tr, ctx_); }
Error CoroReindexer::RollBackTransaction(CoroTransaction& tr) { return impl_->RollBackTransaction(tr, ctx_); }

}  // namespace client
}  // namespace reindexer
