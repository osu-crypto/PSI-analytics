#pragma once

#include <vector>

#include "libOTe/Base/BaseOT.h"

std::vector<uint64_t> evaluate(int N, std::vector<uint64_t> &inputs);


std::vector<uint64_t> masked_evaluate (int N, std::vector<uint64_t> &inputs, std::vector<osuCrypto::block> ot_output);
void benes_route(int n, int lvl_p, int perm_idx, const std::vector<int> &src, const std::vector<int> &dest);

osuCrypto::BitVector return_switches(int N);

void gen_benes_route(int n, int lvl_p, int perm_idx, const std::vector<int> &src, const std::vector<int> &dest);
