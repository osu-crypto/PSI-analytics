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



uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context, const std::vector<std::uint64_t> &ass_data) {


  // establish network connection
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  const auto clock_time_total_start = std::chrono::system_clock::now();
  std::vector<uint64_t> inputs2(inputs), bins;
  int values = context.nbins;
  // int N = int(ceil(log2(context.nbins)));    // Benes network has 2^N inputs
  duration_millis diff;
  uint64_t output = 0;

  if (context.role == CLIENT) {

    //------------(a) osn pre-process---------------------
    const auto offline_osn_start = std::chrono::system_clock::now();
    std::vector<int> dest(values);
    int N = int(ceil(log2(values)));
    int levels = 2*N-1;
    initialize(values, levels);
    std::vector<osuCrypto::block> ot_output = gen_benes_server_osn(values, context, dest);
    const auto offline_osn_finish = std::chrono::system_clock::now();
    diff = offline_osn_finish - offline_osn_start;
    context.timings.offosn = diff.count();

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PID) { 

      std::vector<std::vector<uint64_t>> _inputs(inputs2.size());
      for (int i=0; i< inputs2.size(); ++i)
        _inputs[i].push_back(inputs2[i]);
      std::vector<uint64_t> oprf_out1 = ot_receiver(inputs2, context);
      context.port += 1;
      auto oprf_out2 = ot_sender(_inputs, context);
      context.port += 1;
      for (int i=0; i < inputs2.size(); ++i)
        inputs2[i] = oprf_out1[i] ^ oprf_out2[i][0];

   }

    //------------ (b) circuit-psi preprocessing------------
    const auto psty_start = std::chrono::system_clock::now();

    std::vector<uint64_t> cuckoo_table_v;
    bins = OpprgPsiClient(inputs2, cuckoo_table_v, context); 
    const auto psty_end = std::chrono::system_clock::now();
    diff = psty_end - psty_start;
    context.timings.psty = diff.count();
    //----------------(c)online OSN -------------------------
    std::vector<uint64_t> permuted_bins(values);
    for (int i=0; i < values; ++i) 
      permuted_bins[i] = bins[dest[i]];

    std::string name = "n";
    osuCrypto::IOService ios;
    osuCrypto::Session ep(ios, context.address, context.port + 2, osuCrypto::SessionMode::Server,
                        name);
    auto recvChl = ep.addChannel(name, name);
    std::vector<uint64_t> input_vec(values);
    recvChl.recv(input_vec.data(), input_vec.size());
    // preparing OT outputs
    std::vector<std::vector<osuCrypto::block>> matrix_ot_output(levels, std::vector<osuCrypto::block>(values));
    int ctr = 0;
    for (int i=0; i < levels; ++ i) {
      for (int j=0; j < values/2; ++j)
        matrix_ot_output[i][j] = ot_output[ctr++];
    }
    //output_vec = evaluate(N, input_vec); - for 2^n benes
    gen_benes_masked_evaluate(N, 0, 0, input_vec, matrix_ot_output);

    const auto on_osn_end = std::chrono::system_clock::now();
    diff = on_osn_end - psty_end;
    context.timings.psty = diff.count();

    //-----------------(d) kkrt part ---------------------------
    const auto kkrt_start = std::chrono::system_clock::now();
    std::vector<std::vector<std::uint64_t>> bins2, bins_input; 
    std::vector<std::uint64_t> temp; 
    // permute the bin vector
    for (auto i = 0ull; i < bins.size(); ++i) { 
        temp.push_back(permuted_bins[i] ^ input_vec[i]);
        bins_input.push_back(temp);
        temp.erase(temp.begin(), temp.end());
    }
    bins2 = ot_sender(bins_input, context); //kkrt call 

    osuCrypto::Session ep1(ios, context.address, context.port + 3, osuCrypto::SessionMode::Server,
                        name);
    auto sendChl_pc = ep1.addChannel(name, name);
    for (int i=0; i < bins2.size(); ++i) //translating kkrt output into a single array and sending
      temp.push_back(bins2.at(i).at(0));
    sendChl_pc.asyncSend(temp); 

   const auto kkrt_finish = std::chrono::system_clock::now();
   diff = kkrt_finish - kkrt_start;
   context.timings.kkrt = diff.count();

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::UNION || context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PID) // TO BE MOVED! - 1
    {
      std::cout<<"Computing Set Union: "<<std::endl;
      std::vector<uint64_t> inputs_copy(inputs2.size());
      

      for (int i=0; i < inputs2.size(); ++i)
        inputs_copy[i] = inputs2[i]/100;
      std::sort(inputs_copy.begin(), inputs_copy.end(), std::less<uint64_t>());


      const auto start_s = std::chrono::system_clock::now();
      for (int i=0; i < cuckoo_table_v.size(); ++i) {
        if (!std::binary_search(inputs_copy.begin(), inputs_copy.end(), cuckoo_table_v[i]/100))
          cuckoo_table_v[i] = 0;
      }
      const auto end_s = std::chrono::system_clock::now();
      diff = end_s - start_s;
      std::cout<<"\n binary search time "<<diff.count()<<std::endl;


      std::vector<uint64_t> permuted_table(cuckoo_table_v.size());
      for (int i=0; i < permuted_table.size(); ++i) 
          permuted_table[i] = cuckoo_table_v[dest[i]];
      
      

      std::vector<std::vector<osuCrypto::block>> messages(cuckoo_table_v.size());
      for (int i=0; i < permuted_table.size(); ++i) {
          messages[i].push_back(osuCrypto::toBlock(0, permuted_table[i]));
          messages[i].push_back(osuCrypto::toBlock(0, 0));
      }
      ot_send(messages, context); 
      const auto psu_finish = std::chrono::system_clock::now();
      diff = psu_finish - kkrt_finish;
      std::cout<<"\n final OT step: "<<diff.count();
    }

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::SUM) 
    {
      std::cout<<"Computing Sum: "<<std::endl;
      std::vector<uint64_t> inputs_copy(inputs2.size());
      
      std::vector<std::pair<uint64_t, uint64_t>> target;
      target.reserve(inputs2.size());
      std::transform(inputs2.begin(), inputs2.end(), ass_data.begin(), std::back_inserter(target),
               [](uint64_t a, uint64_t b) { return std::make_pair(a/100, b); });

      std::sort(target.begin(), target.end());

      std::vector<uint64_t> target_first(target.size());
      for (int i=0; i < target.size(); ++i)
        target_first[i] = target[i].first;


      for (int i=0; i < cuckoo_table_v.size(); ++i) {
        std::vector<uint64_t>::iterator it = std::lower_bound(target_first.begin(), target_first.end(), cuckoo_table_v[i]/100);
        if (it == std::end(target_first))
          cuckoo_table_v[i] = 0;
        else
          cuckoo_table_v[i] = target[it-target_first.begin()].second;
      }

      std::vector<uint64_t> permuted_table(cuckoo_table_v.size());
      for (int i=0; i < permuted_table.size(); ++i) 
          permuted_table[i] = cuckoo_table_v[dest[i]];
      
      

      std::vector<std::vector<osuCrypto::block>> messages(cuckoo_table_v.size());
      for (int i=0; i < permuted_table.size(); ++i) {
          messages[i].push_back(osuCrypto::toBlock(0, 0));
          messages[i].push_back(osuCrypto::toBlock(0, permuted_table[i]));
      }
      ot_send(messages, context); 
      const auto psu_finish = std::chrono::system_clock::now();
      diff = psu_finish - kkrt_finish;
      std::cout<<"\n final OT step: "<<diff.count();
    }



  } else {

    //------------(a) osn pre-process---------------------
    const auto offline_osn_start = std::chrono::system_clock::now();
    std::vector<std::vector<uint64_t>> ret_masks = gen_benes_client_osn (values, context);
    const auto offline_osn_end = std::chrono::system_clock::now();
    diff = offline_osn_end - offline_osn_start;
    context.timings.offosn = diff.count();

      if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PID) {

        std::vector<std::vector<uint64_t>> _inputs(inputs2.size());
        for (int i=0; i< inputs2.size(); ++i)
          _inputs[i].push_back(inputs2[i]);
        auto oprf_out1 =  ot_sender(_inputs, context);
        context.port += 1;
        std::vector<uint64_t> oprf_out2 = ot_receiver(inputs2, context);
        context.port += 1;
        for (int i=0; i < inputs2.size(); ++i)
        inputs2[i] = oprf_out1[i][0] ^ oprf_out2[i];

      }
    
    //------------ (b) circuit-psi preprocessing------------
    const auto circuit_psi_start = std::chrono::system_clock::now();
    bins = OpprgPsiServer(inputs2, context); 
    const auto circuit_psi_end = std::chrono::system_clock::now();
    diff = circuit_psi_end - offline_osn_end;
    context.timings.psty = diff.count();
    //---------------- (c) Online OSN -------------------------
    osuCrypto::IOService ios;
    std::string name = "n";
    osuCrypto::Session ep(ios, context.address, context.port + 2, osuCrypto::SessionMode::Client,
                        name);
    auto sendChl = ep.addChannel(name, name);
    std::vector<uint64_t> output_masks, benes_input;

    for (int i = 0; i < bins.size(); ++i) 
      ret_masks[i][0] = ret_masks[i][0] ^ bins[i];
    for (int i = 0; i < values; ++i)
      benes_input.push_back(ret_masks[i][0]);
    sendChl.asyncSend(benes_input);
    for (int i = 0; i < context.nbins; ++i)
      output_masks.push_back(ret_masks[i][1]);

    const auto online_osn_end = std::chrono::system_clock::now();
    diff = online_osn_end - circuit_psi_end;
    context.timings.onosn = diff.count();


    // ------------------------ kkrt part ----------------------
    const auto kkrt_start = std::chrono::system_clock::now();
    std::vector<uint64_t> bins2;
    bins2 = ot_receiver(output_masks, context); //kkrt partx
    osuCrypto::Session ep1(ios, context.address, context.port + 3, osuCrypto::SessionMode::Client,
                        name);
    auto recvChl_pc = ep1.addChannel(name, name);
    std::vector<uint64_t> recv_kkrt(bins2.size());
    recvChl_pc.recv(recv_kkrt.data(), recv_kkrt.size());
    osuCrypto::BitVector char_vec(bins2.size());
    for (int i=0; i < bins2.size();++i) {
      if (recv_kkrt[i] == bins2[i]) {
        char_vec[i] = 1;
        output++;
      }
    }

    const auto kkrt_end = std::chrono::system_clock::now();
    diff = kkrt_end - kkrt_start;
    context.timings.kkrt = diff.count();

    // -------------------kkrt end -------------------------------- 

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::UNION || context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PID) 
    {
      std::vector<uint64_t> rcvMsgUnion;
      std::vector<osuCrypto::block> recvMsg(char_vec.size());
      ot_recv(char_vec, recvMsg, context);
      uint64_t ot_msg[2];
      for (int i=0; i < recvMsg.size(); ++i) {
        memcpy(ot_msg, &recvMsg[i], sizeof(ot_msg)); 
        //std::cout<<"\n check: "<<ot_msg[0]<<" "<<ot_msg[1];
        if (ot_msg[0] != 0)
          rcvMsgUnion.push_back(ot_msg[0]);
      }


      output =  rcvMsgUnion.size() + inputs2.size();

      const auto psu_end = std::chrono::system_clock::now();
      diff = psu_end - kkrt_end;
      std::cout<<"\n final ot step: "<<diff.count();

    }

    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::SUM) 
    {
      output = 0;
      std::vector<uint64_t> rcvMsgUnion;
      std::vector<osuCrypto::block> recvMsg(char_vec.size());
      ot_recv(char_vec, recvMsg, context);
      uint64_t ot_msg[2];
      for (int i=0; i < recvMsg.size(); ++i) {
        memcpy(ot_msg, &recvMsg[i], sizeof(ot_msg)); 
        //std::cout<<"\n check: "<<ot_msg[0]<<" "<<ot_msg[1];
        output += ot_msg[0];
      }

      const auto psu_end = std::chrono::system_clock::now();
      diff = psu_end - kkrt_end;
      std::cout<<"\n final ot step: "<<diff.count();

      std::cout<<"\n output  "<<output;

    }


       
  }

  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();
  
  PrintTimings(context);
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

  benes_route(N, 0, 0, src, dest);
  osuCrypto::u64 len = n;
  osuCrypto::BitVector switches = return_switches(N);

  std::vector<osuCrypto::block> recvMsg(switches.size());
  ot_recv(switches, recvMsg, context);
  return recvMsg;
}

std::vector<osuCrypto::block> server_r_ot_osn(int N, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest) {

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
 
  benes_route(N, 0, 0, src, dest);

  osuCrypto::u64 len = n;
  osuCrypto::BitVector switches = return_switches(N);
  uint64_t temp_msg[2], temp_corr[2];

  osuCrypto::block blk_msg, blk_corr, blk_temp; 
  std::vector<osuCrypto::block> recvMsg(switches.size()), recvCorr(switches.size()), CorrBlks(switches.size());
  rand_ot_recv(switches, recvMsg, context);

  osuCrypto::IOService ios;
  std::string name = "n";
  osuCrypto::Session ep(ios, context.address, context.port + 4, osuCrypto::SessionMode::Server,
                        name);
  auto recvChl_osn = ep.addChannel(name, name);

  for (int i = 0; i < switches.size(); i++) 
    recvChl_osn.recv(recvCorr[i]);
  
  for (int i = 0; i < recvMsg.size(); i++){
      
      if (switches[i] == 1) {
        memcpy(temp_corr, &recvCorr[i], sizeof(temp_corr)); 
        memcpy(temp_msg, &recvMsg[i], sizeof(temp_msg));
        temp_msg[0] = temp_corr[0] ^ temp_msg[0];
        temp_msg[1] = temp_corr[1] ^ temp_msg[1];
        blk_temp = osuCrypto::toBlock(temp_msg[1], temp_msg[0]); 
        recvMsg[i] = blk_temp;
      }

  }

  return recvMsg;
}

std::vector<std::vector<uint64_t>>  client_osn (int N, ENCRYPTO::PsiAnalyticsContext &context) { 
  // assume we are getting the power of two value (N is power of 2)
  int levels = 2 * N - 1; 
  int values = 1 << N; 
  int wires = levels + 1;  
  uint64_t masks[values][wires];
  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // not sure what these parameters mean? fix according to what we need

  for (int i = 0; i < wires; i++) {
    for (int j = 0; j < values; j++) {
      uint64_t temp = prng.get<uint64_t>();
      masks[j][i] = temp; 
    } 
  }
  
  std::vector<std::vector<osuCrypto::block>> ot_messages;
  int baseline_count = 1;
  int size = values; 
  int switch_count = values / 2; 
  int baseline = 0; 
  std::vector<osuCrypto::block> message_pair; 
  uint64_t left, right; 
  osuCrypto::block m0, m1; 

  //--------------first half-----------------------------------------
  for (int j = 0; j < levels / 2; j++){
    baseline_count = pow(2, j);
    size = values / baseline_count; // you have the size and can figure the baselines
    for (int k = 0; k < baseline_count; k++) {
      switch_count = size / 2; 
      baseline = k * size; 
      uint64_t temp_int[2];
      uint64_t temp_int1[2];
      for (int i = 0; i < switch_count; i++){
          // m0 
        left = masks[baseline + 2*i][j] ^ masks[baseline + i][j + 1];
        right = masks[baseline + 2*i + 1][j] ^ masks[baseline + size / 2 + i][j + 1];
        m0 = osuCrypto::toBlock(right, left);
        message_pair.push_back(m0);
          // m1
        right = masks[baseline + 2*i + 1][j] ^ masks[baseline + i][j + 1]; 
        left = masks[baseline + 2*i][j] ^ masks[baseline + size / 2 + i][j + 1];
        m1 = osuCrypto::toBlock(right, left);
        message_pair.push_back(m1); 
        ot_messages.push_back(message_pair);
        message_pair.clear(); 
      }

    }
    
  } 

          //---------------------------middle layer---------------------------
 for (int j = 0; j < values / 2; j++){
    //m0
    left = masks[2*j][levels / 2] ^ masks[2*j][levels / 2 + 1];
    right = masks[2*j + 1][levels / 2] ^ masks[2*j + 1][levels / 2 + 1];
    m0 = osuCrypto::toBlock(right, left);
    message_pair.push_back(m0); 
    //m1
    left = masks[2*j][levels / 2] ^ masks[2*j + 1][levels / 2 + 1];
    right = masks[2*j + 1][levels / 2] ^ masks[2*j][levels / 2 + 1];
    m1 = osuCrypto::toBlock(right, left);
    message_pair.push_back(m1); 
    ot_messages.push_back(message_pair);
    message_pair.clear(); 
}
        
        //-----------------------------second half-------------------------------------
  for(int i = levels / 2 + 1; i < levels; i++) { 
    baseline_count = pow(2, levels - i - 1); // (levels - 1 - (j - 1))
    size = values / baseline_count; // you have the size and can figure the baselines
    
    for (int k = 0; k < baseline_count; k++) {
      baseline = k * size; 
      switch_count = size / 2; 
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
        ot_messages.push_back(message_pair);
        message_pair.clear(); 
      }
    }

  } 
  ot_send(ot_messages, context);
  std::vector<std::vector<uint64_t>> ret_masks(values); // # of wire levels is one more than the # of switch levels
  for (int i= 0; i < values; ++i) {
    ret_masks[i].push_back(masks[i][0]);
    ret_masks[i].push_back(masks[i][levels]);
  }
  return ret_masks;

}


void prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<uint64_t> &src, std::vector<std::array<osuCrypto::block,2>> &ot_output, std::vector<osuCrypto::block> &correction_blocks) {

  // ot message M0 = m0 ^ w0 || m1 ^ w1
  //  for each switch: top wire m0 w0 - bottom wires m1, w1
  //  M1 = m0 ^ w1 || m1 ^ w0
  int levels, i, j, x, s;
  std::vector<uint64_t> bottom1;
  std::vector<uint64_t> top1;
  int values = src.size();
  uint64_t temp;

  uint64_t m0, m1, w0, w1, M0[2], M1[2], corr_mesg[2];
  osuCrypto::block corr_block, temp_block;

  if (values == 2) {
    if (n == 1) {

      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[lvl_p*(Val/2)+perm_idx][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[lvl_p*(Val/2)+perm_idx][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[lvl_p*(Val/2)+perm_idx] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[lvl_p*(Val/2)+perm_idx][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;
      //std::cout<<" base index: "<<(lvl_p)*(Val/2)+perm_idx
      //  <<" m0 = "<<m0<<" "<<" m1 = "<<m1<<" w0 = "<<w0<<" "<<" w1 = "<<w1<<std::endl;


    }
    else {
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[(lvl_p+1)*(Val/2)+perm_idx][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(lvl_p+1)*(Val/2)+perm_idx][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(lvl_p+1)*(Val/2)+perm_idx] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(lvl_p+1)*(Val/2)+perm_idx][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;
      //std::cout<<" base index: "<<(lvl_p + 1)*(Val/2)+perm_idx
      //  <<" m0 = "<<m0<<" "<<" m1 = "<<m1<<" w0 = "<<w0<<" "<<" w1 = "<<w1<<std::endl;


    }
    return; 
  }

  if (values == 3) {
      
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[lvl_p*(Val/2)+perm_idx][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[lvl_p*(Val/2)+perm_idx][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[lvl_p*(Val/2)+perm_idx] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[lvl_p*(Val/2)+perm_idx][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;




      m0 = src[1];
      m1 = src[2];
      temp_block = ot_output[(lvl_p+1)*(Val/2)+perm_idx][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(lvl_p+1)*(Val/2)+perm_idx][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(lvl_p+1)*(Val/2)+perm_idx] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(lvl_p+1)*(Val/2)+perm_idx][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[1] = w0;
      src[2] = w1;

      
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[(lvl_p+2)*(Val/2)+perm_idx][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(lvl_p+2)*(Val/2)+perm_idx][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(lvl_p+2)*(Val/2)+perm_idx] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(lvl_p+2)*(Val/2)+perm_idx][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;

    return;
  }
  
  levels = 2 * n - 1;
   
  // partea superioara
  for (i = 0; i < values-1; i += 2) {


      m0 = src[i];
      m1 = src[i ^ 1];
      temp_block = ot_output[(lvl_p)*(Val/2)+perm_idx+i/2][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(lvl_p)*(Val/2)+perm_idx+i/2][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(lvl_p)*(Val/2)+perm_idx+i/2] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(lvl_p)*(Val/2)+perm_idx+i/2][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[i] = w0;
      src[i ^ 1] = w1;

      bottom1.push_back(src[i]); 
      top1.push_back(src[i^1]);
    }

  if (values % 2 == 1){
    top1.push_back(src[values-1]);
  }


  prepare_correction(n - 1, Val, lvl_p + 1, perm_idx, bottom1, ot_output, correction_blocks);
  prepare_correction(n - 1, Val, lvl_p + 1, perm_idx + values / 4, top1, ot_output, correction_blocks);


  //partea inferioara
  for (i = 0; i < values-1; i += 2) {


      m1 = top1[i/2];
      m0 = bottom1[i/2];
      temp_block = ot_output[(lvl_p + levels - 1)*(Val/2)+perm_idx+i/2][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(lvl_p + levels - 1)*(Val/2)+perm_idx+i/2][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(lvl_p + levels - 1)*(Val/2)+perm_idx+i/2] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(lvl_p + levels - 1)*(Val/2)+perm_idx+i/2][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[i] = w0;
      src[i ^ 1] = w1;

  }

  int idx =int(ceil(values*0.5));
  if (values % 2 == 1) {
    src[values-1] = top1[idx-1];
  }

}

std::vector<osuCrypto::block> gen_benes_server_osn(int values, ENCRYPTO::PsiAnalyticsContext &context, std::vector<int> &dest) {
  
  const auto offline_osn_start = std::chrono::system_clock::now();
  int temp;
  int m = context.nbins;
  std::vector<int> src(values);
  for (int i=0; i < src.size();++i)
    src[i] = dest[i] = i;
  
  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // we need to modify this seed 

  for (int i=m-1; i > 0; i--) {
    int loc = prng.get<uint64_t>() % (i+1);  //  pick random location in the array
    temp = dest[i];
    dest[i] = dest[loc];
    dest[loc] = temp;
  }
  int N = int(ceil(log2(values)));

  gen_benes_route(N, 0, 0, src, dest);
  //osuCrypto::u64 len = n;
  osuCrypto::BitVector switches = return_gen_benes_switches(values);
  osuCrypto::BitVector choices = switches; 

  osuCrypto::IOService ios;
  std::string name = "n";

  std::vector<osuCrypto::block> recvMsg(switches.size());
  std::vector<osuCrypto::block> recvCorr(switches.size());

  if (context.ot == 0) {
    silent_ot_recv(choices, recvMsg, context);
    osuCrypto::BitVector bit_correction = switches ^ choices;

    osuCrypto::Session ep1(ios, context.address, context.port + 15, osuCrypto::SessionMode::Client,
                        name);
    auto sendChl_bcorr = ep1.addChannel(name, name);
  
    /*std::vector<osuCrypto::block> bit_vec(bit_correction.size());
    for (int i=0; i < bit_vec.size(); ++i) {
      bit_vec[i] =  osuCrypto::toBlock(0, int(bit_correction[i]));
    }*/
    //std::cout<<"\n sending bit vector: "<<bit_correction;
    sendChl_bcorr.send(bit_correction);
    sendChl_bcorr.close(); 

  }
  else
    rand_ot_recv(switches, recvMsg, context);


  osuCrypto::Session ep(ios, context.address, context.port + 6, osuCrypto::SessionMode::Server,
                        name);
  auto recvChl_osn = ep.addChannel(name, name);


  recvChl_osn.recv(recvCorr.data(), recvCorr.size());

  uint64_t temp_msg[2], temp_corr[2];
  for (int i = 0; i < recvMsg.size(); i++){
      if (switches[i] == 1) {
        memcpy(temp_corr, &recvCorr[i], sizeof(temp_corr)); 
        memcpy(temp_msg, &recvMsg[i], sizeof(temp_msg));
        temp_msg[0] = temp_corr[0] ^ temp_msg[0];
        temp_msg[1] = temp_corr[1] ^ temp_msg[1];
        recvMsg[i] = osuCrypto::toBlock(temp_msg[1], temp_msg[0]);  
      }
  }
  
  const auto offline_osn_finish = std::chrono::system_clock::now();
  duration_millis diff = offline_osn_finish - offline_osn_start;
  //std::cout<<"\n offline osn: "<<diff.count();
  return recvMsg;
}

std::vector<std::vector<uint64_t>>  gen_benes_client_osn (int values, ENCRYPTO::PsiAnalyticsContext &context) { 
  
  const auto offline_osn_start = std::chrono::system_clock::now();
  int N = int(ceil(log2(values)));

  int levels = 2*N-1;
  int switches = levels*(values/2);  
  uint64_t temp;
  std::vector<uint64_t> masks(values);
  std::vector<std::vector<uint64_t>> ret_masks(values);

  osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); 

  for (int j = 0; j < values; j++) { // we sample the input masks randomly
      temp = prng.get<uint64_t>();
      masks[j] = temp; 
      ret_masks[j].push_back(temp);
  } 
  
  const auto rand_ot_start = std::chrono::system_clock::now();
  std::vector<std::array<osuCrypto::block,2>> ot_messages(switches);
  osuCrypto::IOService ios;
  std::string name = "n";

  if (context.ot == 0)  {
    osuCrypto::BitVector bit_correction(switches); 
    silent_ot_send(ot_messages, context); //sample random ot blocks
    osuCrypto::Session ep1(ios, context.address, context.port + 15, osuCrypto::SessionMode::Server,
                        name);
    auto recvChl_bcorr = ep1.addChannel(name, name);
  

    //std::vector<osuCrypto::block> bit_vec(bit_correction.size());
    recvChl_bcorr.recv(bit_correction);
    /*uint64_t temp_arr[2];
    for (int i=0; i < bit_vec.size(); ++i) {
      memcpy(temp_arr, &bit_vec[i], sizeof(temp_arr)); 
      bit_correction[i] = temp_arr[0];
    }*/
    //std::cout << "bit correction " << bit_correction << std::endl;
    recvChl_bcorr.close();
    //std::cout<<"\n received bit vector: "<<bit_correction;

    osuCrypto::block tmp;
     for (int k = 0; k < ot_messages.size(); k++) {
        if(bit_correction[k] == 1){
          tmp = ot_messages[k][0];
          ot_messages[k][0] = ot_messages[k][1];
          ot_messages[k][1] = tmp; 
        }
      }
  }
  else
    rand_ot_send(ot_messages, context); //sample random ot blocks

  
  std::vector<osuCrypto::block> correction_blocks(switches); 
  
  prepare_correction(N, values, 0, 0, masks, ot_messages, correction_blocks);

  // create a channel and send correction_blocks
 
  osuCrypto::Session ep(ios, context.address, context.port + 6, osuCrypto::SessionMode::Client,
                        name);
  auto sendChl_osn = ep.addChannel(name, name);

  //for (int i = 0; i < correction_blocks.size(); i++) {
  //    //std::cout<<" sending correction block: "<<correction_blocks[i]<<std::endl;
  //    sendChl_osn.send(correction_blocks[i]);
  //}
  sendChl_osn.asyncSend(correction_blocks);


  for (int i= 0; i < values; ++i) {
    ret_masks[i].push_back(masks[i]);
  }
  const auto offline_osn_finish = std::chrono::system_clock::now();
  
  duration_millis diff = offline_osn_finish - offline_osn_start;
  //std::cout << "\n offline osn: " << diff.count();
  return ret_masks;

}

std::vector<uint64_t> OpprgPsiClient(const std::vector<uint64_t> &elements, 
                      std::vector<uint64_t> &cuckoo_table_v,
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

  cuckoo_table_v = cuckoo_table.AsRawVector();

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
  //std::cout << "Client: circuit-psi " << total_duration.count() << std::endl; 
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
  //std::cout << "Server: circuit-psi pre-processing " << total_duration.count(); 
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
  std::cout << "\nTime for offline OSN " << context.timings.offosn << " ms\n";
  std::cout << "Time for PSTY preprocess " << context.timings.psty << " ms\n";
  std::cout << "Time for online OSN " << context.timings.onosn << " ms\n";
  std::cout << "Time for kkrt "
            << context.timings.kkrt << " ms\n";

  std::cout << "Total runtime: " << context.timings.total << "ms\n";

}

}



void test_gen_benes() {


  int i, j, values, levels;
  values = 13;
  int N = int(ceil(log2(values)));
  levels = 2 * N- 1;

    
  std::vector<int> dest(values);
  std::vector<int> src(values);
    
  for (i = 0; i < values; ++i)
    src[i] = i;

  for (i = 0; i < values; ++i)
    dest[i] = i;


  dest[0] = 6;
  dest[1] = 5;
  dest[2] = 0;
  dest[3] = 7;
  dest[4] = 12;
  dest[5] = 2;
  dest[6] = 11;
  dest[7] = 8;
  dest[8] = 10;
  dest[9] = 1;
  dest[10] = 4;
  dest[11] = 3;
  dest[12] = 9;

  
  gen_benes_route(N, 0, 0, src, dest);


  std::vector<uint64_t> input(values);
  for (i = 0; i < values; ++i)
    input[i] = i;

  gen_benes_eval(N, 0, 0, input);

  std::cout<<"\n\n";
  for (int i=0; i < values;++i)
    std::cout<<input[i]<<" ";
  std::cout<<"\n\n";

  std::vector<std::vector<osuCrypto::block>> ot_output(levels, std::vector<osuCrypto::block>(values));
  for (i = 0; i < values; ++i)
    input[i] = i;

  gen_benes_masked_evaluate(N, 0, 0, input, ot_output);

  std::cout<<"\n\n";
  for (int i=0; i < values;++i)
    std::cout<<input[i]<<" ";
  std::cout<<"\n\n";

  osuCrypto::BitVector b= return_gen_benes_switches(values);

  //std::cout<<"bit vector: "<<b;


}