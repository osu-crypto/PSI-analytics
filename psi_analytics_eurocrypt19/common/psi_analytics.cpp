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

#include "benes.h"
#include "psi_analytics.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"

#include "ots/ots.h"
#include "polynomials/Poly.h"


#include "libOTe/Base/BaseOT.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "psi_analytics_context.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>
#include <vector>
#include <cmath>

#include <bits/stdc++.h> 

namespace ENCRYPTO {

using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context) {
  // establish network connection
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  const auto clock_time_total_start = std::chrono::system_clock::now();

  // create hash tables from the elements
  std::vector<uint64_t> bins;

   int N = int(ceil(log2(context.nbins)));    // Benes network has 2^N inputs

  if (context.role == CLIENT) {
    
    std::vector<std::vector<uint64_t>> ret_masks = client_osn(N, context); //  OSN related pre-processing

    bins = OpprgPsiClient(inputs, context); // circuit-psi preprocessing 

    // --------------- Online OSN -----------------------------------------
    for (int i = 0; i < bins.size(); ++i) {
      //std::cout << "inputs masks " << ret_masks[i][0] << std::endl;
      ret_masks[i][0] = ret_masks[i][0] ^ bins[i]; // size of bins < size of masks
      //std::cout << "online masked input " << ret_masks[i][0] << std::endl;
    }

    osuCrypto::IOService ios;
    std::string name = "n";
    osuCrypto::Session ep(ios, context.address, context.port + 2, osuCrypto::SessionMode::Client,
                        name);
    auto sendChl = ep.addChannel(name, name);

    std::vector<uint64_t> output_masks;

    for (int i = 0; i < ret_masks.size(); ++i) {
      sendChl.send(ret_masks[i][0]);   //  sending masked input vector
      //std::cout<<" "<<ret_masks[i][0];
    }

    for (int i = 0; i < context.nbins; ++i) {
      output_masks.push_back(ret_masks[i][1]);
    }


    // ------------------------ kkrt part ----------------------
    std::vector<uint64_t> bins2;
    bins2 = ot_receiver(output_masks, context);

    
    for (auto i = 0ull; i < bins2.size(); ++i) {
        std::cout << i << std:: endl; 
        std::cout << "client side: output of oprf - 1" << bins[i] << std::endl; 
        //std::cout << "client side: output of osn " << output_masks[i] << std::endl;
        std::cout << "client side: output of oprf - 2 " << bins2[i] << std::endl;
    }
    //-----------------------------kkrt --------------------------
  } else {

    std::vector<int> dest(1 << N);
    std::vector<osuCrypto::block> ot_output = server_osn(N, context, dest);

    bins = OpprgPsiServer(inputs, context); // circuit-psi preprocessing


    std::vector<uint64_t> permuted_bins(context.nbins);

    for (int i=0; i < permuted_bins.size(); ++i) {
      std::cout << "dest " << i << " " << dest[i] << std::endl; 
      permuted_bins[dest[i]] = bins[i];
    }

   

   //--------------------- online OSN ----------------

    std::vector<uint64_t> input_vec(1<<N), output_vec;

    std::string name = "n";
    osuCrypto::IOService ios;
    osuCrypto::Session ep(ios, context.address, context.port + 2, osuCrypto::SessionMode::Server,
                        name);
    auto recvChl = ep.addChannel(name, name);
    for (int i = 0; i < (1 << N); ++i) {
      recvChl.recv(input_vec[i]);
      std::cout<< input_vec[i] << std::endl;
    }
    //output_vec = evaluate(N, input_vec);
    output_vec = masked_evaluate(N, input_vec, ot_output);


    //-------------------kkrt part ---------------------------
    
    // permute the bin vector


    std::vector<std::vector<std::uint64_t>> bins2; 
    std::vector<std::vector<std::uint64_t>> bins_input; 
    std::vector<std::uint64_t> temp; 
    for (auto i = 0ull; i < bins.size(); ++i) { 
        //temp.push_back(permuted_bins[i] ^ output_vec[i]);
        // for plain eval we need permuted_bins[i] ^ output_vec[i] == 0 
        //std::cout << "permuted xor output_vec " << (permuted_bins[i] ^ output_vec[i]) << std::endl;
        temp.push_back(permuted_bins[i] ^ output_vec[i]);
        bins_input.push_back(temp);
        temp.erase(temp.begin(), temp.end());
    }

    
    bins2 = ot_sender(bins_input, context);

    /* receive the strings fro client for local comparison
    std::vector<std::uint64_t> client_output(context.nbins);
    osuCrypto::BitVector char_vec(context.nbins);
    for (int i = 0; i < context.nbins; ++i) {
      recvChl.recv(client_output[i]);
      char_vec[i] = (client_output[i] == bins2[i][0]);
    }*/

    
    for (auto i = 0ull; i < bins2.size(); ++i) {
    std::cout << "server side position i = " << i <<  "size" <<  bins2.at(i).size() << std::endl;
      for (auto j = 0ull; j < bins2.at(i).size(); ++j) {
        std::cout << "server side: output of oprf - 1 " << bins[i] << std::endl; 
        //std::cout << "server side: output after permuted output_vec " << output_vec[i] << std::endl;
        std::cout << "server side: output of oprf - 2 " << i << j << " value " << bins2.at(i).at(j) <<  std::endl; 
        
      }
    }
    // -------------------kkrt end -------------------------------- 
   
  }

  /* instantiate ABY
  ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                 context.nthreads);
  party.ConnectAndBaseOTs();
  auto bc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_BOOL)->GetCircuitBuildRoutine());  // GMW circuit
  assert(bc);

  share_ptr s_in_server, s_in_client;

  // share inputs in ABY
  if (context.role == SERVER) {
    s_in_server = share_ptr(bc->PutSIMDINGate(bins.size(), bins.data(), context.maxbitlen, SERVER));
    s_in_client = share_ptr(bc->PutDummySIMDINGate(bins.size(), context.maxbitlen));
  } else {
    s_in_server = share_ptr(bc->PutDummySIMDINGate(bins.size(), context.maxbitlen));
    s_in_client = share_ptr(bc->PutSIMDINGate(bins.size(), bins.data(), context.maxbitlen, CLIENT));
  }

  // compare outputs of OPPRFs for each bin in ABY (using SIMD)
  auto s_eq = share_ptr(bc->PutEQGate(s_in_server.get(), s_in_client.get()));

  std::vector<share_ptr> bin_results;
  for (uint32_t i = 0; i < bins.size(); ++i) {
    uint32_t pos[] = {i};
    bin_results.emplace_back(bc->PutSubsetGate(s_eq.get(), pos, 1));
    bin_results.at(i) = share_ptr(bc->PutOUTGate(bin_results.at(i).get(), ALL));
  }

  share_ptr s_out;
  auto t_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.threshold)));
  auto s_threshold = share_ptr(bc->PutCONSGate(context.threshold, t_bitlen));
  std::uint64_t const_zero = 0;
  auto s_zero = share_ptr(bc->PutCONSGate(const_zero, 1));

  if (context.analytics_type == PsiAnalyticsContext::NONE) {
    // we want to only do benchmarking, so no additional operations
  } else if (context.analytics_type == PsiAnalyticsContext::THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    s_out = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM_IF_GT_THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    auto s_gt_t = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
    s_out = share_ptr(bc->PutMUXGate(s_out.get(), s_zero.get(), s_gt_t.get()));
  } else {
    throw std::runtime_error("Encountered an unknown analytics type");
  }

  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
  }

  party.ExecCircuit();

  uint64_t output = 0;
  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    output = s_out->get_clear_value<uint64_t>();
  }

  context.timings.aby_setup = party.GetTiming(P_SETUP);
  context.timings.aby_online = party.GetTiming(P_ONLINE);
  context.timings.aby_total = context.timings.aby_setup + context.timings.aby_online;
  context.timings.base_ots_aby = party.GetTiming(P_BASE_OT);
*/
  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();

  uint64_t output = 0; 
  return output;
}

std::vector<osuCrypto::block> server_osn(int N, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest) {

  int temp;
  int n = 1 << N;
  int m = context.nbins;
  std::vector<int> src(n);
  for (int i=0; i < dest.size();++i)
    src[i] = dest[i] = i;
  
  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // we need to modify this seed 

  for (int i=m-1; i > 0; i--) {
    int loc = prng.get<uint64_t>() % (i+1);  //  pick random location in the array
    temp = dest[i];
    dest[i] = dest[loc];
    dest[loc] = temp;
  }

/*
  std::cout<<"Testing generated permutation where m= "<<m<<std::endl;
  for (int i=0; i < perm.size(); ++i)
    std::cout<<" "<<perm[i];
  std::cout<<std::endl;
*/
  benes_route(N, 0, 0, src, dest);
  osuCrypto::u64 len = n;
  osuCrypto::BitVector switches = return_switches(N);

  std::vector<osuCrypto::block> recvMsg(switches.size());
  ot_recv(switches, recvMsg, context);
  //std::cout<<"test - "<<m<<" "<<n<<" "<<switches.size()<<" "<<recvMsg.size();
  return recvMsg;
}


std::vector<std::vector<uint64_t>>  client_osn (int N, ENCRYPTO::PsiAnalyticsContext &context) { 
  // assume we are getting the power of two value
  // if N is not a power of 2, fix accordingly for the generalized benes network
  int levels = 2 * N - 1; 
  int values = 1 << N; 
  int wires = levels + 1;  
  //uint64_t masks[values][wires]; // # of wire levels is one more than the # of switch levels
  uint64_t masks[values][wires];
  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // not sure what these parameters mean? fix according to what we need

  for (int i = 0; i < wires; i++) {
    //std::cout << "i = " << i << std::endl; 
    for (int j = 0; j < values; j++) {
      uint64_t temp = prng.get<uint64_t>();
      masks[j][i] = temp; 
      //std::cout << "masks" << j << " "<< i << " "<<  masks[j][i] << std::endl; 
    } 
  }

    
  /* ---------------------testing blocks and xor ------------------------
  uint64_t dummy1[2];
  dummy1[0] = masks[0][0];
  dummy1[1] = masks[0][1];
  std::cout << dummy1[0] << std::endl;
  std::cout << dummy1[1] << std::endl; 
  osuCrypto::block dummy2 = osuCrypto::toBlock(dummy1[1], dummy1[0]);
  std::cout << "block " << dummy2 << std::endl; 
  
  // check 
  // can retrieve values of the block but in flipped order
  memcpy(dummy1, &dummy2, sizeof(dummy1));
  std::cout << "val - left" << dummy1[0] << std::endl;
  std::cout << "val - right" << dummy1[1] << std::endl;
  */

// ------------------------------benes first half -------------------------
  std::vector<std::vector<osuCrypto::block>> ot_messages;
  int baseline_count = 1;
  int size = values; 
  int switch_count = values / 2; 
  int baseline = 0; 
  std::vector<osuCrypto::block> message_pair; 
  uint64_t left, right; 
  osuCrypto::block m0, m1; 
  for (int j = 0; j < levels / 2; j++){
    //std::cout << "j = " << j << std::endl; 
    baseline_count = pow(2, j);
    size = values / baseline_count; // you have the size and can figure the baselines
    for (int k = 0; k < baseline_count; k++) {
      switch_count = size / 2; 
      baseline = k * size; 
      for (int i = 0; i < switch_count; i++){
          // m0 
        left = masks[baseline + 2*i][j] ^ masks[baseline + i][j + 1];
        right = masks[baseline + 2*i + 1][j] ^ masks[baseline + size / 2 + i][j + 1];
        m0 = osuCrypto::toBlock(right, left);
        message_pair.push_back(m0);
        /*if (j == 0 && i == 0 && baseline == 0) {
          std::cout << "left" << left << std::endl; 
          std::cout << "right" << right << std::endl; 
          std::cout << "m0 = " << m0 << std::endl; 
          std::cout << "message pair = " << message_pair.at(0) << std::endl; 
          //std::cout << "ot_messages = " << ot_messages.at(0).at(1) << std::endl; 
          a = left;
        }

        if (j == 1 && i == 0 && baseline == 0) {
          std::cout << "left" << left << std::endl; 
          std::cout << "right" << right << std::endl; 
          std::cout << "m0 = " << m0 << std::endl; 
          std::cout << "message pair = " << message_pair.at(0) << std::endl; 
          //std::cout << "ot_messages = " << ot_messages.at(0).at(1) << std::endl; 
          b = left; 
        }*/
        
        
          // m1
        right = masks[baseline + 2*i + 1][j] ^ masks[baseline + i][j + 1]; 
        left = masks[baseline + 2*i][j] ^ masks[baseline + size / 2 + i][j + 1];
        m1 = osuCrypto::toBlock(right, left);
        message_pair.push_back(m1); 
        /*if(j == 2 && i == 0) {
          std::cout << "mp"  << message_pair.at(0) << std::endl; 
          std::cout << "mp"  << message_pair.at(1) << std::endl; 
        }*/

        ot_messages.push_back(message_pair);
        message_pair.clear(); 
      }

    }
    
  } 
  /*std::cout << ot_messages.at(16).at(0) << std::endl;
  std::cout << ot_messages.at(16).at(1) << std::endl;
  std::cout << ot_messages.at(18).at(0) << std::endl;
  std::cout << ot_messages.at(18).at(1) << std::endl;
  std::cout << ot_messages.at(20).at(0) << std::endl;
  std::cout << ot_messages.at(20).at(1) << std::endl;*/
  /*std::cout << "a " << a << std::endl;
    std::cout << "b " << b << std::endl;
    std::cout << "c " << (a ^ b) << std::endl;
    std::cout << "c " << (masks[0][0] ^ masks[0][2]) << std::endl;*/




  
  for(int i = levels / 2; i < (levels - 1); i++) {

    //std::cout << "i = " << i << std::endl; 
    baseline_count = pow(2, levels - i - 2); // (levels - 1 - (j - 1))
    size = values / baseline_count; // you have the size and can figure the baselines
    
    for (int k = 0; k < baseline_count; k++) {
      baseline = k * size; 
      //std::cout << "baseline  = " << baseline << std::endl; 
      switch_count = size / 2; 
      //std::cout << "switch count = " << switch_count << std::endl; 
      for (int j = 0; j < switch_count; j++){
        // m0
        left = masks[baseline + j][i] ^ masks[baseline + 2 * j][i + 1];
        right = masks[baseline + size / 2 + j][i] ^ masks[baseline + 2 * j + 1][i + 1];
        m0 = osuCrypto::toBlock(right, left);
        // m1
        left = masks[baseline + j][i] ^ masks[baseline + 2 * j + 1][i + 1];
        right = masks[baseline + size / 2 + j][i] ^ masks[baseline + 2 * j][i + 1];
        m1 = osuCrypto::toBlock(right, left);


        message_pair.push_back(m0);
        message_pair.push_back(m1); 
        /*if(j == 0 && i == 4) {
          std::cout << "mp"  << message_pair.at(0) << std::endl; 
          std::cout << "mp"  << message_pair.at(1) << std::endl; 
        }*/
        ot_messages.push_back(message_pair);
        message_pair.clear(); 
      }
    }

  } 
 /* std::cout << ot_messages.at(32).at(0) << std::endl;
  std::cout << ot_messages.at(32).at(1) << std::endl;
  std::cout << ot_messages.at(36).at(0) << std::endl;
  std::cout << ot_messages.at(36).at(1) << std::endl;*/
 
  //std::cout << "ot_messages size " << ot_messages.size() << std::endl; 

  for (int i = 0; i < values / 2; i++){

    // m0
        left = masks[2*i][levels - 1] ^ masks[2*i][levels];
        right = masks[2*i + 1][levels - 1] ^ masks[2*i + 1][levels];
        m0 = osuCrypto::toBlock(right, left);
        // m1
        left = masks[2*i][levels - 1] ^ masks[2*i + 1][levels];
        right = masks[2*i + 1][levels - 1] ^ masks[2*i][levels];
        m1 = osuCrypto::toBlock(right, left);


        message_pair.push_back(m0);
        message_pair.push_back(m1); 
        /*if(i == 1 || i == 0) {
          std::cout << "mp"  << message_pair.at(0) << std::endl; 
          std::cout << "mp"  << message_pair.at(1) << std::endl; 
        }*/
        ot_messages.push_back(message_pair);
        message_pair.clear(); 
  }

  //std::cout<<"test - "<<ot_messages.size();

  ot_send(ot_messages, context);

  std::vector<std::vector<uint64_t>> ret_masks(values); // # of wire levels is one more than the # of switch levels
  for (int i= 0; i < values; ++i) {
    ret_masks[i].push_back(masks[i][0]);
    ret_masks[i].push_back(masks[i][levels]);
  }

  return ret_masks;

   /* std::cout << ot_messages.at(48).at(0) << std::endl;
    std::cout << ot_messages.at(48).at(1) << std::endl;
    std::cout << ot_messages.at(49).at(0) << std::endl;
    std::cout << ot_messages.at(49).at(1) << std::endl;*/
}

std::vector<uint64_t> OpprgPsiClient(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();
  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
  cuckoo_table.SetNumOfHashFunctions(context.nfuns);
  cuckoo_table.Insert(elements);
  cuckoo_table.MapElements();
  // cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  auto cuckoo_table_v = cuckoo_table.AsRawVector();

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();
  const auto oprf_start_time = std::chrono::system_clock::now();

  std::vector<uint64_t> masks_with_dummies = ot_receiver(cuckoo_table_v, context);
  
  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);
  
  const auto receiving_start_time = std::chrono::system_clock::now();
  
  sock->Receive(poly_rcv_buffer.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();
  
  const auto receiving_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = receiving_end_time - receiving_start_time;
  context.timings.polynomials_transmission = sending_duration.count();

  const auto eval_poly_start_time = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }

  const auto eval_poly_end_time = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
  context.timings.polynomials = eval_poly_duration.count();

  std::vector<uint64_t> raw_bin_result;
  raw_bin_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    raw_bin_result.push_back(X[i].elem ^ Y[i].elem);
  }

  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;
  context.timings.total = total_duration.count();

  return raw_bin_result;
}

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();

  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
  simple_table.SetNumOfHashFunctions(context.nfuns);
  simple_table.Insert(elements);
  simple_table.MapElements();
  // simple_table.Print();

  auto simple_table_v = simple_table.AsRaw2DVector();
  // context.simple_table = simple_table_v;

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  const auto oprf_start_time = std::chrono::system_clock::now();

  auto masks = ot_sender(simple_table_v, context);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  const auto polynomials_start_time = std::chrono::system_clock::now();

  std::vector<uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<uint64_t> dist(0,
                                               (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  InterpolatePolynomials(polynomials, content_of_bins, masks, context);

  const auto polynomials_end_time = std::chrono::system_clock::now();
  const duration_millis polynomials_duration = polynomials_end_time - polynomials_start_time;
  context.timings.polynomials = polynomials_duration.count();
  const auto sending_start_time = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((uint8_t *)polynomials.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto sending_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = sending_end_time - sending_start_time;
  context.timings.polynomials_transmission = sending_duration.count();
  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;

  return content_of_bins;
}

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context) {
  std::size_t nbins = masks.size();
  std::size_t masks_offset = 0;
  std::size_t nbinsinmegabin = ceil_divide(nbins, context.nmegabins);

  for (auto mega_bin_i = 0ull; mega_bin_i < context.nmegabins; ++mega_bin_i) {
    auto polynomial = polynomials.begin() + context.polynomialsize * mega_bin_i;
    auto bin = content_of_bins.begin() + nbinsinmegabin * mega_bin_i;
    auto masks_in_bin = masks.begin() + nbinsinmegabin * mega_bin_i;

    if ((masks_offset + nbinsinmegabin) > masks.size()) {
      auto overflow = (masks_offset + nbinsinmegabin) % masks.size();
      nbinsinmegabin -= overflow;
    }

    InterpolatePolynomialsPaddedWithDummies(polynomial, bin, masks_in_bin, nbinsinmegabin, context);
    masks_offset += nbinsinmegabin;
  }

  assert(masks_offset == masks.size());
}

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<uint64_t>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context) {
  std::uniform_int_distribution<std::uint64_t> dist(0,
                                                    (1ull << context.maxbitlen) - 1);  // [0,2^61)
  std::random_device urandom("/dev/urandom");
  auto my_rand = [&urandom, &dist]() { return dist(urandom); };

  std::vector<ZpMersenneLongElement> X(context.polynomialsize), Y(context.polynomialsize),
      coeff(context.polynomialsize);

  for (auto i = 0ull, bin_counter = 0ull; i < context.polynomialsize;) {
    if (bin_counter < nbins_in_megabin) {
      if ((*masks_for_elems_in_bin).size() > 0) {
        for (auto &mask : *masks_for_elems_in_bin) {
          X.at(i).elem = mask & __61_bit_mask;
          Y.at(i).elem = X.at(i).elem ^ *random_value_in_bin;
          ++i;
        }
      }
      ++masks_for_elems_in_bin;
      ++random_value_in_bin;  // proceed to the next bin (iterator)
      ++bin_counter;
    } else {  // generate dummy elements for polynomial interpolation
      X.at(i).elem = my_rand();
      Y.at(i).elem = my_rand();
      ++i;
    }
  }

  Poly::interpolateMersenne(coeff, X, Y);

  auto coefficient = coeff.begin();
  for (auto i = 0ull; i < coeff.size(); ++i, ++polynomial_offset, ++coefficient) {
    *polynomial_offset = (*coefficient).elem;
  }
}

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role) {
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2) {
  std::vector<std::uint64_t> intersection_v;

  std::sort(v1.begin(), v1.end());
  std::sort(v2.begin(), v2.end());

  std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(intersection_v));
  return intersection_v.size();
}

void PrintTimings(const PsiAnalyticsContext &context) {
  std::cout << "Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << "Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << "Time for polynomials " << context.timings.polynomials << " ms\n";
  std::cout << "Time for transmission of the polynomials "
            << context.timings.polynomials_transmission << " ms\n";
//  std::cout << "Time for OPPRF " << context.timings.opprf << " ms\n";

 /* std::cout << "ABY timings: online time " << context.timings.aby_online << " ms, setup time "
            << context.timings.aby_setup << " ms, total time " << context.timings.aby_total
            << " ms\n";
*/
  std::cout << "Total runtime: " << context.timings.total << "ms\n";
 /* std::cout << "Total runtime w/o base OTs: "
            << context.timings.total - context.timings.base_ots_aby -
                   context.timings.base_ots_libote
            << "ms\n";*/
}

}

 /* ---------------------testing blocks and xor ------------------------
  uint64_t dummy1[2];
  dummy1[0] = masks[0][0];
  dummy1[1] = masks[0][1];
  std::cout << dummy1[0] << std::endl;
  std::cout << dummy1[1] << std::endl; 
  osuCrypto::block dummy2 = osuCrypto::toBlock(dummy1[0], dummy1[1]);
  std::cout << "block " << dummy2 << std::endl; 
  
  // check 
  uint64_t c = masks[0][0] ^ masks[0][1];
  uint64_t b = c ^ masks[0][0];
  uint64_t a = c ^ b; 
  std::cout << masks[0][0] << std::endl;
  std::cout << masks[0][1] << std::endl; 
  std::cout << "c = " << c << std::endl; 
  std::cout << "b = " << b << std::endl; 
  std::cout << "a = " << a << std::endl; */