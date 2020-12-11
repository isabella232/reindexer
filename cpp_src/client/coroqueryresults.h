#pragma once

#include <chrono>
#include "client/item.h"
#include "client/resultserializer.h"

namespace reindexer {
class TagsMatcher;
namespace net {
namespace cproto {
class CoroClientConnection;
}
}  // namespace net

namespace client {

using std::chrono::seconds;
using std::chrono::milliseconds;

class Namespace;
using NSArray = h_vector<Namespace*, 1>;

class CoroQueryResults {
public:
	CoroQueryResults(int fetchFlags = 0);
	CoroQueryResults(const CoroQueryResults&) = delete;
	CoroQueryResults(CoroQueryResults&&) = default;
	CoroQueryResults& operator=(const CoroQueryResults&) = delete;
	CoroQueryResults& operator=(CoroQueryResults&& obj) = default;

	class Iterator {
	public:
		Error GetJSON(WrSerializer& wrser, bool withHdrLen = true);
		Error GetCJSON(WrSerializer& wrser, bool withHdrLen = true);
		Error GetMsgPack(WrSerializer& wrser, bool withHdrLen = true);
		Item GetItem();
		int64_t GetLSN();
		bool IsRaw();
		string_view GetRaw();
		Iterator& operator++();
		Error Status() const noexcept{ return qr_->status_; }
		bool operator!=(const Iterator&other) const noexcept { return idx_ != other.idx_; }
		bool operator==(const Iterator&other) const noexcept { return idx_ == other.idx_; };
		Iterator& operator*() { return *this; }
		void readNext();
		void getJSONFromCJSON(string_view cjson, WrSerializer& wrser, bool withHdrLen = true);

		const CoroQueryResults* qr_;
		int idx_, pos_, nextPos_;
		ResultSerializer::ItemParams itemParams_;
	};

	Iterator begin() const { return Iterator{this, 0, 0, 0, {}}; }
	Iterator end() const { return Iterator{this, queryParams_.qcount, 0, 0, {}}; }

	size_t Count() const { return queryParams_.qcount; }
	int TotalCount() const { return queryParams_.totalcount; }
	bool HaveRank() const { return queryParams_.flags & kResultsWithRank; }
	bool NeedOutputRank() const { return queryParams_.flags & kResultsNeedOutputRank; }
	const string& GetExplainResults() const { return queryParams_.explainResults; }
	const vector<AggregationResult>& GetAggregationResults() const { return queryParams_.aggResults; }
	Error Status() { return status_; }
	h_vector<string_view, 1> GetNamespaces() const;
	bool IsCacheEnabled() const { return queryParams_.flags & kResultsWithItemID; }

	TagsMatcher getTagsMatcher(int nsid) const;

private:
	friend class RPCClient;
	friend class CoroRPCClient;
	friend class RPCClientMock;
	CoroQueryResults(net::cproto::CoroClientConnection* conn, NSArray&& nsArray, int fetchFlags, int fetchAmount, seconds timeout);
	CoroQueryResults(net::cproto::CoroClientConnection* conn, NSArray&& nsArray, string_view rawResult, int queryID,
				 int fetchFlags, int fetchAmount, seconds timeout);
	void Bind(string_view rawResult, int queryID);
	void fetchNextResults();

	net::cproto::CoroClientConnection* conn_;

	NSArray nsArray_;
	h_vector<char, 0x100> rawResult_;
	int queryID_;
	int fetchOffset_;
	int fetchFlags_;
	int fetchAmount_;
	seconds requestTimeout_;

	ResultSerializer::QueryParams queryParams_;
	Error status_;
};
}  // namespace client
}  // namespace reindexer
