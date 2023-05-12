#include <assert.h>

#include <afl-fuzz.h>
#include <types.h>
#include <cmplog.h>

#include "cmp-functions.h"


// CMP attribute enum
enum {

  IS_EQUAL = 1,    // arithemtic equal comparison
  IS_GREATER = 2,  // arithmetic greater comparison
  IS_LESSER = 4,   // arithmetic lesser comparison
  IS_FP = 8,       // is a floating point, not an integer

  // Internal use
  HAS_TRUE = 16
};


typedef struct Angora{
  afl_state_t* afl;

  // The gradient of each dy/dx_i for every cmplog entry
  s32* gradients;

  struct cmp_map cmp_backup;
}Angora;

Angora* afl_custom_init(afl_state_t* afl, unsigned int seed){
    Angora* data = calloc(1, sizeof(Angora));

    data->afl = afl;
    data->gradients = NULL;

    srand(seed);

    return data;
}

long kale_get_gradient_h(struct cmp_map* prev, struct cmp_map* cur, int k, int i, int h){
  // Angora the if statement
  int attributes = cur->headers[k].attribute;
  kale_function_info_t f = kale_get_function_from_type(attributes);
  
  long fprime = f.callback(cur->log[k][i].v0, cur->log[k][i].v1);
  long f0 = f.callback(prev->log[k][i].v0, prev->log[k][i].v1);

  return (fprime - f0) / h;
}

// Gets the gradient between a currently calculated cmp log entry and the original cmplog entry
// k and i are the cmp log entry target and the index of the log
long kale_get_gradient(struct cmp_map* prev, struct cmp_map* cur, u32 k, u32 i){
  kale_get_gradient_h(prev, cur, k, i, 1);
}

// Returns if a cmplog statement evaluated to true
int kale_cmplog_is_true(struct cmp_map* cmplog, u32 k, u32 i){
  // TODO: 128
  kale_function_info_t statementEvaluator = kale_get_function_from_type(cmplog->headers[k].attribute);

  s64 statement = statementEvaluator.callback(cmplog->log[k][i].v0, cmplog->log[k][i].v1);

  return statementEvaluator.constraint(statement);
}

// Returns the index of a false cmplog given an entry in the cmplog, returns u32 max if none
u32 kale_get_false_entry(struct cmp_map* cmplog, u32 k){
    for(u32 i = 0; i < cmplog->headers[k].hits; i++){
      if(!kale_cmplog_is_true(cmplog, k, i)){
        return i;
      }
    }
    
    return UINT32_MAX;
}

// Counts the number of false entries in cmplog
u32 kale_cmplog_false_count(struct cmp_map* cmplog){
  u32 count = 0;
  for(int k = 0; k < CMP_MAP_W; k++){
      if(!cmplog->headers[k].hits) 
        continue;

      u32 i = kale_get_false_entry(cmplog, k);

      if(i == UINT32_MAX){
        cmplog->headers[k].attribute &= ~HAS_TRUE;
      }else{
        count++;
        cmplog->headers[k].attribute += HAS_TRUE;
      }
  }

  return count;
}

// Counts the number of false entries in cmplog
u32 kale_cmplog_count(struct cmp_map* cmplog){
  u32 count = 0;
  for(int k = 0; k < CMP_MAP_W; k++){
      if(!cmplog->headers[k].hits) 
        continue;
      count++;
  }

  return count;
}

// Chooses a target cmplog entry that's false, returning its index
// Returns CMP_MAX_W max if none exists
u32 kale_choose_random_false(struct cmp_map* cmplog){
  // TODO: Verify gradient
  u32 falseCount = kale_cmplog_false_count(cmplog);
  if (falseCount == 0) return CMP_MAP_W;

  u32 target = rand() % falseCount;
  u32 counted = 0;

  // Go to the nth 
  for(int k = 0; k < CMP_MAP_W; k++){
    if(!cmplog->headers[k].hits) continue;
    if(!cmplog->headers[k].attribute & HAS_TRUE) continue;

    if(counted == target) return k;

    counted++;
  }

  assert(false);
  return CMP_MAP_W;
}

u32 kale_choose_random(struct cmp_map* cmplog){
  u32 count = kale_cmplog_count(cmplog);
  if(count == 0) return CMP_MAP_W;

  u32 target = rand() % count;
  u32 counted = 0;


  for(int k = 0; k < CMP_MAP_W; k++){
    if(!cmplog->headers[k].hits) continue;

    if(counted == target) return k;

    counted++;
  }

  assert(false);
  return CMP_MAP_W;
}

u8 kale_has_gradient(Angora* kale, unsigned size){
  for(int i = 0; i < size; i++){
    if(kale->gradients[i]) return 1;
  }
  return 0;
}

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size){
  return 1;
}

size_t afl_custom_fuzz(void* udata, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size){
  //printf("\nIteration... ");
  int learningRate = 4;
  const int modulationWidth = 10;
  const int modulationThreshold = 5000;
  const int epsilon = 1;
  const int maxIterations = 400;
  const int annealingRate = 50;

  Angora* kale = (Angora*)udata;
  afl_state_t* afl = kale->afl;

  if (unlikely(!afl->orig_cmp_map)) {
    afl->orig_cmp_map = ck_alloc_nozero(sizeof(struct cmp_map));
  }

  if(afl->shm.cmp_map == NULL){
    exit(5115);
  }

  // Select a cmplog entry to start with
  u32 k = kale_choose_random(afl->shm.cmp_map);

  if(k == CMP_MAP_W) return 0;

  u32 i = rand() % (afl->shm.cmp_map->headers[k].hits);

  // backup stuff
  memcpy(&kale->cmp_backup, afl->shm.cmp_map, sizeof(struct cmp_map));

  *out_buf = ck_alloc(buf_size);
  memcpy(*out_buf, buf, buf_size);

  // Reallocate gradients array
  const unsigned spaceNeeded = buf_size * sizeof(s32);
  afl_realloc((void**)&kale->gradients, spaceNeeded);
  memset(kale->gradients, 0, spaceNeeded);

  // Do first cmplog pass
  memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);

  if (unlikely(common_fuzz_cmplog_stuff(afl, *out_buf, buf_size))) {
    // TODO: Error handling
    assert(false);
    return 0;
  }

  // Save the original map
  memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));

  u8 initial_cmp_state = kale_cmplog_is_true(afl->shm.cmp_map, k, i);

  int iterations = 0;  

  int bufIncrement;

  // Modulate the iteration
  // This is because when fuzzing a certain input most of the gradients are likely 0
  // We search only every modulationWidth gradients until we find a gradient
  if(buf_size > modulationThreshold){
    bufIncrement = modulationWidth;
  }else{
    bufIncrement = 1;
  }

  // Continually calculate gradient until it flips
  while(kale_cmplog_is_true(afl->shm.cmp_map, k, i) == initial_cmp_state){

    // Calculate gradients of new input
    for(int j = rand()%modulationWidth; j < buf_size; j += bufIncrement){
      //printf("\rIteration... %d", j);
      memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
      (*out_buf)[j] += epsilon;


      if (unlikely(common_fuzz_cmplog_stuff(afl, *out_buf, buf_size))) {
        // TODO: Error handling
        assert(false);
        return 0;
      }

      // Check if the if statement is no longer present, this could be because the args are equal,
      // just apply another gradient descent and hope
      if(afl->shm.cmp_map->headers[k].hits != afl->orig_cmp_map->headers[k].hits){
        goto descent;
      }

      kale->gradients[j] = kale_get_gradient(afl->orig_cmp_map, afl->shm.cmp_map, k, i);

      (*out_buf)[j] -= epsilon;

      if(kale->gradients[j]){
        bufIncrement = 1;
      }else{
        bufIncrement = modulationWidth;
      }
    }

    // Make sure there is a gradient
    if(!kale_has_gradient(kale, buf_size)) goto failure;

    // Apply gradient descent
    descent:
    for(int j = 0; j < buf_size; j++){
      (*out_buf)[j] += kale->gradients[j] * learningRate;
    }

    // Do first cmplog pass
    memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);

    if (unlikely(common_fuzz_cmplog_stuff(afl, *out_buf, buf_size))) {
      // TODO: Error handling
      assert(false);
      return 0;
    }

    // Save the original map
    memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));

    iterations++;
    if (iterations == maxIterations) goto failure;

    if(annealingRate > 1 && iterations % annealingRate == 0){
        learningRate /= 2;
    }

  }

  // We are done, we have a new input that will evaluate to true
  success:
  // Restore original stuff
  memcpy(afl->shm.cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));

  //printf("\rIteration... Success\n");
  return buf_size;

  failure:
  memcpy(afl->shm.cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));
  ck_free(*out_buf);
  *out_buf = NULL;

  //printf("\rIteration... Failure\n");
  return 0;
}

void afl_custom_deinit(Angora* kale){
  afl_free(kale->gradients);
}
