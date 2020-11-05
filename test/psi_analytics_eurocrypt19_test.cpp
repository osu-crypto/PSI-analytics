//
// \file psi_analytics_eurocrypt19_test.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko

#include <thread>
#include <stdlib.h>
#include <time.h>

#include "gtest/gtest.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

constexpr std::size_t ITERATIONS = 1;

constexpr std::size_t NELES_2_12 = 1ull << 12, NELES_2_16 = 1ull << 16, NELES_2_20 = 1ull << 20;
constexpr std::size_t POLYNOMIALSIZE_2_12 = 975, POLYNOMIALSIZE_2_16 = 1021,
                      POLYNOMIALSIZE_2_20 = 1024;
constexpr std::size_t NMEGABINS_2_12 = 16, NMEGABINS_2_16 = 248, NMEGABINS_2_20 = 4002;

auto CreateContext(e_role role, uint64_t neles, uint64_t polynomialsize, uint64_t nmegabins) {
  return ENCRYPTO::PsiAnalyticsContext{7777,  // port
                                       role,
                                       61,  // bitlength
                                       neles,
                                       static_cast<uint64_t>(neles * 1.27f),
                                       0,  // # other party's elements, i.e., =neles
                                       1,  // # threads
                                       3,  // # hash functions
                                       1,  // threshold
                                       polynomialsize,
                                       polynomialsize * sizeof(uint64_t),
                                       nmegabins,
                                       1.27f,  // epsilon
                                       "127.0.0.1",
                                       ENCRYPTO::PsiAnalyticsContext::NONE};
}

void PsiAnalyticsCardinalityTest(std::size_t elem_bitlen, uint64_t neles, uint64_t polynomialsize,
                      uint64_t nmegabins) {
  
  

  auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
  auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);


  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 61, 1);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 61, 2);
  for (int i=0; i < neles/2; ++i)
    client_inputs[i] = server_inputs[i];
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);



  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_server, plain_intersection_size);
  }

}

void PsiAnalyticsUnionTest(std::size_t elem_bitlen, uint64_t neles, uint64_t polynomialsize,
                      uint64_t nmegabins) {
  neles = 10;
  auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
  auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);
  client_context.analytics_type = ENCRYPTO::PsiAnalyticsContext::UNION ;
  server_context.analytics_type = ENCRYPTO::PsiAnalyticsContext::UNION ;

  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 61, 1);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 61, 2);
  srand (time(NULL));
  uint64_t r = rand() % (neles/2) + 1;
  for (int i=0; i < r; ++i)
    client_inputs[i] = server_inputs[i];

  std::cout<<"\n the r = "<<r<<" neles = "<<neles;
  std::cout<<"client input"<<std::endl;
  for (int i=0; i < client_inputs.size(); ++i)
    std::cout<<client_inputs[i]<<std::endl;
  std::cout<<"server input"<<std::endl;
  for (int i=0; i < server_inputs.size(); ++i)
    std::cout<<server_inputs[i]<<std::endl;
  std::cout<<std::endl;
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_server, server_inputs.size()+client_inputs.size()-r);

  }

}


void PsiAnalyticsPIDTest(std::size_t elem_bitlen, uint64_t neles, uint64_t polynomialsize,
                      uint64_t nmegabins) {
  
  auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
  auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);
  client_context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PID ;
  server_context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PID ;

  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 61, 1);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 61, 2);
  for (int i=0; i < neles/2; ++i)
    client_inputs[i] = server_inputs[i];
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

  }

}




TEST(PSI_ANALYTICS, pow_2_12) {

  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsCardinalityTest(61, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_16) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsCardinalityTest(61, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  } 
}

TEST(PSI_ANALYTICS, pow_2_20) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsCardinalityTest(61, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
  } 
}


/*
TEST(PSI_ANALYTICS, union_pow_2_12) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsUnionTest(61, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}



TEST(PSI_ANALYTICS, pid_pow_2_12) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsPIDTest(61, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}



TEST(PSI_ANALYTICS, union_pow_2_16) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsUnionTest(61, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  } 
}

TEST(PSI_ANALYTICS, pid_pow_2_16) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsPIDTest(61, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  } 
}


*/

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}