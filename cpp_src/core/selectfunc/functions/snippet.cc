#include "snippet.h"
#include "core/selectfunc/ctx/ftctx.h"
#include "highlight.h"
#include "tools/errors.h"

namespace reindexer {

bool Snippet::process(ItemRef &res, PayloadType &pl_type, const SelectFuncStruct &func) {
	if (!func.ctx) return false;
	if (func.funcArgs.size() < 4) throw Error(errParams, "Invalid snippet params need minimum 4 - have %d", int(func.funcArgs.size()));

	FtCtx::Ptr ftctx = reinterpret_pointer_cast<FtCtx>(func.ctx);
	AreaHolder::Ptr area = ftctx->Area(res.id);
	if (!area) return false;
	Payload pl(pl_type, res.value);

	KeyRefs kr;
	pl.Get(func.field, kr);
	const string *data = p_string(kr[0]).getCxxstr();

	auto pva = area->GetAreas(func.fieldNo);
	if (!pva || pva->empty()) return false;
	auto &va = *pva;
	int front = 0;
	int back = data->size();
	try {
		back = stoi(func.funcArgs[2]);
	} catch (std::exception e) {
		throw Error(errParams, "Invalid snippet param back - %s is not a number", func.funcArgs[2].c_str());
	}

	try {
		front = stoi(func.funcArgs[3]);
	} catch (std::exception e) {
		throw Error(errParams, "Invalid snippet param front - %s is not a number", func.funcArgs[3].c_str());
	}

	vector<Area> sva(*area->GetAreas(func.fieldNo));

	for (auto &a : sva) {
		a.start_ -= calcUTf8SizeEnd(data->data() + a.start_, a.start_, back);
		if (a.start_ < 0 || back < 0) a.start_ = 0;
		a.end_ += calcUTf8Size(data->data() + a.end_, data->size() - a.end_, front);
		if (size_t(a.end_) > data->size() || front < 0) a.end_ = int(data->size());
	}
	if (!sva.empty()) {
		for (auto vit = sva.begin() + 1; vit != sva.end(); ++vit) {
			auto prev = vit - 1;
			if (vit->Concat(*prev)) {
				vit = sva.erase(prev);
			}
		}
	}
	int offset = 0;
	int snippet_offset = 0;

	int va_offset = 0;

	string result_string;
	result_string.reserve(data->size());
	int cur_pos = 0;
	for (auto &area : sva) {
		offset = offset - (area.start_ - snippet_offset);
		snippet_offset = area.end_;
		cur_pos = result_string.size();
		result_string.insert(result_string.end(), data->begin() + area.start_, data->begin() + area.end_);
		for (; size_t(va_offset) < va.size(); ++va_offset) {
			if (area.IsIn(va[va_offset].start_, true) || area.IsIn(va[va_offset].end_, true)) {
				int start = va[va_offset].start_ + offset;
				if (start < 0) start = 0;

				result_string.insert(start, func.funcArgs[0]);
				offset += func.funcArgs[0].size();
				int end = va[va_offset].end_ + offset;
				if (size_t(end) > result_string.size() - 1) end = result_string.size();
				result_string.insert(end, func.funcArgs[1]);
				offset += func.funcArgs[1].size();
			} else {
				break;
			}
		}
		if (func.funcArgs.size() > 5) {
			result_string.append(func.funcArgs[5]);
			offset += func.funcArgs[5].size();
		} else {
			result_string.append(" ");
			offset++;
		}
		if (func.funcArgs.size() > 4) {
			result_string.insert(cur_pos, func.funcArgs[4]);
			offset += func.funcArgs[4].size();
		}
	}

	key_string_release(const_cast<string *>(data));
	auto str = make_key_string(result_string);
	key_string_add_ref(str.get());
	res.value.AllocOrClone(0);

	pl.Set(func.field, KeyRefs{KeyRef{str}});
	return true;
}

}  // namespace reindexer
