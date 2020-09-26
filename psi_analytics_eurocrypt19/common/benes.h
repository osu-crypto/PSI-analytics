#pragma once

#include <vector>

#include "libOTe/Base/BaseOT.h"

void evaluate(int N, std::vector<int> &inputs);

void benes_route(int n, int lvl_p, int perm_idx, const std::vector<int> &src, const std::vector<int> &dest);

osuCrypto::BitVector return_switches(int N);