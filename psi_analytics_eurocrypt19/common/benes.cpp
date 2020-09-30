
#include <cstdio>
#include <cstring>
#include <vector>
#include <iostream>
#include <math.h>
using namespace std;

#include <cryptoTools/Common/BitVector.h>

const int max_dim = 13;

int perm[1 << max_dim];
int inv_perm[1 << max_dim];

char switched[2 * max_dim - 1][1 << (max_dim - 1)];

char path[1 << max_dim];    


osuCrypto::BitVector return_switches(int N) {

  int values = 1 << N;
  int levels = 2*N - 1;
  osuCrypto::BitVector switches(values*levels/2);
  for (int j=0; j < levels; ++j)
    for (int i=0; i < values/2; ++i) {
      switches[(values*j)/2 +i] = switched[j][i];
      //std::cout<<" . "<<int(switched[i][j])<<" -> "<<switches[values*j+i];
    }
  return switches;
}                     


void DFS(int idx, int route) {

  //std::cout << "entered the dfs function_call ()" << std::endl; 
  path[idx] = route;

  if (path[idx ^ 1] < 0) // if the next item in the vertical array is unassigned 
  	DFS(idx ^ 1, route ^ 1); /// the next item is always assigned the opposite of this item, unless it was part of path/cycle of previous node

  idx = perm[inv_perm[idx] ^ 1]; // inv_perm[idx] - gives the position of the output, idx connects to?
 
  if (path[idx] < 0)
  	DFS(idx, route ^ 1);
}

int shuffle(int i, int n) { 
	return ((i & 1) << (n - 1)) | (i >> 1); 
}

void benes_route(int n, int lvl_p, int perm_idx, const vector<int> &src, const vector<int> &dest) {

  int values, levels, i, j, x, s;
  vector<int> bottom1;
  vector<int> top1;
  
  /*std::cout << "in level p = " << lvl_p << std::endl; 
  std::cout<< "permutation index = " << perm_idx << std::endl; */
  if (n == 1) {
  	switched[lvl_p][perm_idx] = src[0] != dest[0]; 
  	return; 
  }
  
  values = 1 << n;
  //std::cout << "values is set to " << values << std::endl; 
  levels = 2 * n - 1;
  //std::cout << "number of levels is set to " << levels << std::endl; 
  
  vector<int> bottom2(values / 2);
  vector<int> top2(values / 2);

  /*std::cout << "in level p = " << lvl_p << std::endl; 
  for (i = 0; i < values; ++i) {
    std::cout << "src[i] = " << src[i] << endl;
  }

  for (i = 0; i < values; ++i) {
    std::cout << "dest[i] = " << dest[i] << endl;
  }*/

  for (i = 0; i < values; ++i) {
  	inv_perm[src[i]] = i;
    //std::cout << "inv_perm" << src[i] << inv_perm[src[i]] << std::endl; 
    }
 
  for (i = 0; i < values; ++i){
  	perm[i] = inv_perm[dest[i]];
    //std::cout << "perm" << i << perm[i] << std::endl; 
    }

  for (i = 0; i < values; ++i) {
  	inv_perm[perm[i]] = i;
    //std::cout << "inv_perm" << perm[i] << i << std::endl; 
    }
 
  memset(path, -1, sizeof(path));
  //std::cout << "size of the path " << sizeof(path) << std::endl; 
  for (i = 0; i < values; ++i)
  	if (path[i] < 0)
  		DFS(i, 0);


  for (i = 0; i < values; i += 2) {
    switched[lvl_p][perm_idx + i / 2] = path[i];
    for (j = 0; j < 2; ++j) {
      x = shuffle((i | j) ^ path[i], n);
      if (x < values / 2) bottom1.push_back(src[i | j]); 
      else top1.push_back(src[i | j]);
    }
  }

  for (i = 0; i < values; i += 2) {
    s = switched[lvl_p + levels - 1][perm_idx + i / 2] = path[perm[i]];
    for (j = 0; j < 2; ++j) {
      x = shuffle((i | j) ^ s, n);
      if (x < values / 2) bottom2[x] = src[perm[i | j]]; 
      else top2[x - values / 2] = src[perm[i | j]];
    }
  }

  benes_route(n - 1, lvl_p + 1, perm_idx, bottom1, bottom2);
  benes_route(n - 1, lvl_p + 1, perm_idx + values / 4, top1, top2);
  return; 
}

// baseline: is in terms of the values, not switches
// size: is in terms of the wires/values, not switches


void fwd_propagate (int size, int baseline, int level, vector<uint64_t> &source, vector<uint64_t> &dest, vector<osuCrypto::block> &ot_msgs) {
  //std::cout << "in fwd propagate " << std::endl; 
  int switch_count = size / 2;
  osuCrypto::block temp_block; 
  uint64_t temp_int[2]; 
  for (int j = 0; j < switch_count; j++){
      temp_block = ot_msgs.at(0);
      ot_msgs.erase(ot_msgs.begin());
      memcpy(temp_int, &temp_block, sizeof(temp_int));
      
      if (switched[level][baseline / 2 + j] == 0) {
        dest[baseline + j] = source[baseline + 2*j] ^ temp_int[0];
        dest[baseline + size / 2 + j] = source[baseline + 2*j + 1] ^ temp_int[1];
        
        
      }
      else {
        dest[baseline + j] = source[baseline + 2*j + 1] ^ temp_int[1];
        dest[baseline + size / 2 + j] = source[baseline + 2*j] ^ temp_int[0];
        
      }
  }

}

void f_propagate (int size, int baseline, int level, vector<uint64_t> &source, vector<uint64_t> &dest) {
  //std::cout << "in fwd propagate " << std::endl; 
  int switch_count = size / 2;
  //osuCrypto::block temp_block; 
  //uint64_t temp_int[2]; 
  for (int j = 0; j < switch_count; j++){
      //temp_block = ot_msgs.at(0);
      //ot_msgs.erase(ot_msgs.begin());
      //memcpy(temp_int, &temp_block, sizeof(temp_int));
      if (switched[level][baseline / 2 + j] == 0) {
        dest[baseline + j] = source[baseline + 2*j];
        dest[baseline + size / 2 + j] = source[baseline + 2*j + 1];
      }
      else {
        dest[baseline + j] = source[baseline + 2*j + 1];
        dest[baseline + size / 2 + j] = source[baseline + 2*j];
      }
  }

 /* std::cout << "We are in level: " << level << std::endl; 
  for (int i = 0; i < size; i ++){
    std::cout << "source" << source[baseline + i] << " " << dest[baseline + i] << std::endl; 
  }*/

}

void rev_propagate (int size, int baseline, int level, vector<uint64_t> &source, vector<uint64_t> &dest, vector<osuCrypto::block> &ot_msgs) {
  //std::cout << "in rev propagate " << std::endl; 
  int switch_count = size / 2; 
  osuCrypto::block temp_block; 
  uint64_t temp_int[2];
  for (int j = 0; j < switch_count; j++){
      temp_block = ot_msgs.at(0);
      memcpy(temp_int, &temp_block, sizeof(temp_int));
      ot_msgs.erase(ot_msgs.begin());
      if (switched[level][baseline / 2 + j] == 0) {
        dest[baseline + 2 * j] = source[baseline + j] ^ temp_int[0];
        dest[baseline + 2 * j + 1] = source[baseline + size / 2 + j] ^ temp_int[1];
      }
      else {
        dest[baseline + 2 * j] = source[baseline + size / 2 + j] ^ temp_int[1];
        dest[baseline + 2 * j + 1] = source[baseline + j] ^ temp_int[0];
      }
  }

  /*std::cout << "We are in level: " << level << std::endl; 
  for (int i = 0; i < size; i ++){
    std::cout << "source" << source[baseline + i] << " " << dest[baseline + i] << std::endl; 
  }*/

}

void r_propagate (int size, int baseline, int level, vector<uint64_t> &source, vector<uint64_t> &dest) {
  //std::cout << "in rev propagate " << std::endl; 
  int switch_count = size / 2; 
  osuCrypto::block temp_block; 
  uint64_t temp_int[2];
  for (int j = 0; j < switch_count; j++){
      //temp_block = ot_msgs.at(0);
      //ot_msgs.erase(ot_msgs.begin());
      if (switched[level][baseline / 2 + j] == 0) {
        dest[baseline + 2 * j] = source[baseline + j];
        dest[baseline + 2 * j + 1] = source[baseline + size / 2 + j];
      }
      else {
        dest[baseline + 2 * j] = source[baseline + size / 2 + j];
        dest[baseline + 2 * j + 1] = source[baseline + j];
      }
  }

  /*std::cout << "We are in level: " << level << std::endl; 
  for (int i = 0; i < size; i ++){
    std::cout << "source" << source[baseline + i] << " " << dest[baseline + i] << std::endl; 
  }*/

}

vector<uint64_t> masked_evaluate (int N, vector<uint64_t> &inputs, vector<osuCrypto::block> ot_output) {
    int values = 1 << N; 
    int levels = 2 * N - 1; 
    int size = values;
    int baseline_count = 1; 
    vector<uint64_t> temp(inputs.size());
    //cout << "size of ot_output " << ot_output.size() << std::endl;
    vector<osuCrypto::block> ot_masks = ot_output; 
    //std::cout << "first ot message" << ot_masks.at(0) << std::endl; 
    //std::cout << "second message ot" << ot_masks.at(1) << std::endl;
    int toggle = 0; 
    //forward 
    for (int j = 0; j < levels / 2; j++){
      baseline_count = pow(2, j);
      size = values / baseline_count; // you have the size and can figure the baselines

      if (toggle % 2 == 0){
          for (int k = 0; k < baseline_count; k++) {
            fwd_propagate(size, k * size , j, inputs, temp, ot_masks);
            
          }
          toggle++; 
      } 
      else {
          for (int k = 0; k < baseline_count; k++) {
            fwd_propagate(size, k * size , j, temp, inputs, ot_masks);
          }
          toggle++;
      }

    }

    osuCrypto::block temp_block; 
    uint64_t temp_int[2];
    if (toggle % 2 == 0) {
      for (int j = 0; j < values / 2; j++){
          temp_block = ot_masks.at(0);
          ot_masks.erase(ot_masks.begin());
          if (switched[levels/2][j] == 1) { 
            temp[2 * j + 1] = inputs[2 * j] ^ temp_int[0];
            temp[2 * j] = inputs[2 * j + 1] ^ temp_int[1];
          }
          else {
            temp[2 * j + 1] = inputs[2 * j + 1] ^ temp_int[1];
            temp[2 * j] = inputs[2 * j] ^ temp_int[0];
          }
        }
        /*for (int j = 0; j < values; j++){
          std::cout << temp[j] << std::endl; 
        }*/
        toggle++;
    }
    else {
      for (int j = 0; j < values / 2; j++){
          temp_block = ot_masks.at(0);
          ot_masks.erase(ot_masks.begin());
          if (switched[levels/2][j] == 1) { 
            inputs[2 * j + 1] = temp[2 * j] ^ temp_int[0];
            inputs[2 * j] = temp[2 * j + 1] ^ temp_int[1];
          }
          else {
            inputs[2 * j + 1] = temp[2 * j + 1] ^ temp_int[1];
            inputs[2 * j] = temp[2 * j] ^ temp_int[0];
          }
        }
        /*for (int j = 0; j < values; j++){
          std::cout << inputs[j] << std::endl; 
        }*/
        toggle++;
    }

     
    for(int j = levels / 2 - 1; j >= 0; j--) {
      baseline_count = pow(2, j);
      size = values / baseline_count; // you have the size and can figure the baselines

      if (toggle % 2 == 0){
          for (int k = 0; k < baseline_count; k++) {
            rev_propagate(size, k * size , levels - (j + 1), inputs, temp, ot_masks);
          }

          toggle++; 
      } 
      else {
          for (int k = 0; k < baseline_count; k++) { 
            rev_propagate(size, k * size , levels - (j + 1), temp, inputs, ot_masks);
          }
          toggle++;
      }

    }
  //std::cout << "in benes/evaluate()" << std::endl; 
  if (toggle % 2 == 0) {
    //for (int i = 0; i < values; i ++)
      //std::cout << inputs[i] << std::endl; 
    return inputs;
  }
  else {
    //for (int i = 0; i < values; i ++)
      //std::cout << temp[i] << std::endl;  
    return temp;
  }

}

  vector<uint64_t> evaluate (int N, vector<uint64_t> &inputs) {
    int values = 1 << N; 
    int levels = 2 * N - 1; 
    int size = values;
    int baseline_count = 1; 
    vector<uint64_t> temp(inputs.size());
    int toggle = 0; 
    //forward 
    for (int j = 0; j < levels / 2; j++){
      baseline_count = pow(2, j);
      size = values / baseline_count; // you have the size and can figure the baselines

      if (toggle % 2 == 0){
          for (int k = 0; k < baseline_count; k++) {
            f_propagate(size, k * size , j, inputs, temp);
          }
          toggle++; 
      } 
      else {
          for (int k = 0; k < baseline_count; k++) {
            f_propagate(size, k * size , j, temp, inputs);
          }
          toggle++;
      }

    }

    if (toggle % 2 == 0) {
      for (int j = 0; j < values / 2; j++){
          if (switched[levels/2][j] == 1) { 
            temp[2 * j + 1] = inputs[2 * j];
            temp[2 * j] = inputs[2 * j + 1];
          }
          else {
            temp[2 * j + 1] = inputs[2 * j + 1];
            temp[2 * j] = inputs[2 * j];
          }
        }
       
        toggle++;
    }
    else {
      for (int j = 0; j < values / 2; j++){
          if (switched[levels/2][j] == 1) { 
            inputs[2 * j + 1] = temp[2 * j];
            inputs[2 * j] = temp[2 * j + 1];
          }
          else {
            inputs[2 * j + 1] = temp[2 * j + 1];
            inputs[2 * j] = temp[2 * j];
          }
        }
        
        toggle++;
    }
  
    for(int j = levels / 2 - 1; j >= 0; j--) {
      baseline_count = pow(2, j);
      size = values / baseline_count; // you have the size and can figure the baselines

      if (toggle % 2 == 0){
          for (int k = 0; k < baseline_count; k++) {
            r_propagate(size, k * size , levels - (j + 1), inputs, temp);
          }

          toggle++; 
      } 
      else {
          for (int k = 0; k < baseline_count; k++) { 
            r_propagate(size, k * size , levels - (j + 1), temp, inputs);
          }
          toggle++;
      }

    }
  //std::cout << "in benes/evaluate()" << std::endl; 
  if (toggle % 2 == 0) {
    //for (int i = 0; i < values; i ++)
      //std::cout << inputs[i] << std::endl; 
    return inputs;
  }
  else {
    //for (int i = 0; i < values; i ++)
      //std::cout << temp[i] << std::endl; 
    return temp;  
  }

} 



/* --------------------------------------------------------------------
------------------wrong benes structure---------------------------------
void propagate (int N, int perm_idx, int lvl_p, vector<int> &source, vector<int> &destination) {
  int switch_count = 1 << (N - 1); 
  int values = 1 << N;
  for (int j = 0; j < switch_count; j++){
      if (switched[lvl_p][j] == 0) {
        destination[perm_idx + j] = source[perm_idx + 2*j];
        destination[perm_idx + values/2 + j] = source[perm_idx + 2*j + 1];
      }
      else {
        destination[perm_idx + j] = source[perm_idx + 2*j + 1];
        destination[perm_idx + values/2 + j] = source[perm_idx + 2*j];
      }
  }
  for (int i = 0; i < values; i ++){
    std::cout << "source" << source[i] << " " << destination[i] << std::endl; 
  }

}

vector<int> evaluate (int N, int lvl_p, vector<int> &inputs) { // need to add another 2d vector here called masks
  // include a check to see that size of inputs matches up 
  int values = 1 << N;
  int levels = 2 * N - 1;
  cout << "levels is " << levels << std::endl;  
  vector<int> temp(inputs.size());
  for (int i = 0; i < levels; i++) {
     if (i % 2  == 0) 
        propagate(N, i, inputs, temp);
     else 
        propagate(N, i, temp, inputs);
    }
  
  if (lvl_p % 2 == 0) {
    for (int i = 0; i < values; i ++)
      std::cout << temp[i] << std::endl; 
    return temp;
  }
  else {
    for (int i = 0; i < values; i ++)
      std::cout << inputs[i] << std::endl; 
    return inputs; 
  }

}
--------------------------------------------------------------------------------------*/


/* -----------------want single main function---------------------------------------------
int main() {

  int N, i, j, values, levels;
  bool first = true;

 // while (scanf("%i", &N) == 1, N) {
    N = 4; 
    values = 1 << N;
    levels = 2 * N - 1;
    
    vector<int> dest(values);
    vector<int> src(values);
    
    for (i = 0; i < values; i++) {
      src[i] = i; 
      
      //std::cout << "enter the src vector " << i << std::endl; 
    	//scanf("%i", &src[i]);
      std::cout << "(pos, src)" << i << " " << src[i] << std::endl; 
    }

    
  
    
  
    

    for (i = 0; i < values; i++) {
      //std::cout << "enter the value " << i << std::endl; 
    	scanf("%i", &dest[i]);
      std::cout << "(pos, dest)" << i << " " << dest[i] << std::endl; 
    }

    benes_route(N, 0, 0, src, dest);

    if (!first)
    	printf("\n");
    else first = false;

    for (i = 0; i < levels; ++i) {
      for (j = 0; j < values / 2; ++j) { // need to do a similar thing while connecting to the OT
      	if (switched[i][j] == 0)
      		printf("straight ");
      	else
      		printf("cross ");
      }
      printf("\n");
    }


   evaluate(N, src);
    for (i = 0; i < values; i++) {
        std::cout << src[i] << " " << permuted_inputs[i] << std::endl; 
    }
  //}
  return 0;
}*/

//--------------------------------------------------------------------