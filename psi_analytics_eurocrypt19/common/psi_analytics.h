#pragma once
//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
#include "helpers.h"
#include "psi_analytics_context.h"

#include "libOTe/Base/BaseOT.h"


#include <vector>

namespace ENCRYPTO {

static std::vector<uint64_t> DEFAULT_VECTOR;


//uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context);
uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context, const std::vector<std::uint64_t> &ass_data = DEFAULT_VECTOR);



std::vector<std::vector<uint64_t>>  client_osn (int N, ENCRYPTO::PsiAnalyticsContext &context);

std::vector<osuCrypto::block> server_osn (int N, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest); 


std::vector<osuCrypto::block> gen_benes_server_osn(int values, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest);

void prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<uint64_t> &src, std::vector<std::array<osuCrypto::block,2>> &ot_output, std::vector<osuCrypto::block> &correction_blocks);

std::vector<std::vector<uint64_t>>  gen_benes_client_osn (int values, ENCRYPTO::PsiAnalyticsContext &context);



std::vector<std::vector<uint64_t>>  client_r_ot_osn (int N, ENCRYPTO::PsiAnalyticsContext &context);

std::vector<osuCrypto::block> server_r_ot_osn (int N, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest); 

std::vector<uint64_t> OpprgPsiClient(const std::vector<uint64_t> &elements,
                          std::vector<uint64_t> &cuckoo_table_v,
                                     PsiAnalyticsContext &context);

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context);

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context);

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<uint64_t>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context);

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role);

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2);

void PrintTimings(const PsiAnalyticsContext &context);
}

void test_gen_benes();