#include <assert.h>

#include <afl-fuzz.h>
#include <types.h>
#include <cmplog.h>
#include <xxhash.h>
#include "map.h"

#include "cmp-functions.h"

#ifdef DEBUG
#define PRINT(...) printf(__VA_ARGS__)
#else
#define PRINT(...) 
#endif

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

  unsigned char* out_buf;

  struct cmp_map cmp_backup;

  XXH64_state_t* hash_state;
  void* map;
}Angora;

Angora* afl_custom_init(afl_state_t* afl, unsigned int seed){
    Angora* data = calloc(1, sizeof(Angora));

    data->hash_state = XXH64_createState();
    data->map = kale_map_create();
    data->afl = afl;
    data->gradients = NULL;
    data->out_buf = NULL;

    srand(seed);


    return data;
}

// Gets the gradient between a currently calculated cmp log entry and the original cmplog entry
// k and i are the cmp log entry target and the index of the log
long kale_get_gradient(struct cmp_map* prev, struct cmp_map* cur, int k, int i, int h){
  if (cur->headers[k].hits <= i) return 0;

  // Angora the if statement
  int attributes = cur->headers[k].attribute;
  kale_function_info_t f = kale_get_function_from_type(attributes);
  
  long fprime = f.callback(cur->log[k][i].v0, cur->log[k][i].v1);
  long f0 = f.callback(prev->log[k][i].v0, prev->log[k][i].v1);

  return (fprime - f0) / h;
}

// Returns if a cmplog statement evaluated to true
int kale_cmplog_is_true(struct cmp_map* cmplog, u32 k, u32 i, s64* statement){

  // TODO: 128
  kale_function_info_t statementEvaluator = kale_get_function_from_type(cmplog->headers[k].attribute);

  *statement = statementEvaluator.callback(cmplog->log[k][i].v0, cmplog->log[k][i].v1);

  PRINT("%llu vs %llu  %ld  %d  %d\n", cmplog->log[k][i].v0, cmplog->log[k][i].v1, *statement, statementEvaluator.constraint(*statement), cmplog->headers[k].hits > i);

  return statementEvaluator.constraint(*statement);
}

int kale_cmplog_is_true_or_missing(struct cmp_map* cmplog, u32 k, u32 i, s64* statement, unsigned int attr, bool expected){
  // if the cmplog entry is missing and its an equality, then we can just assume that its ok
  if(cmplog->headers[k].hits <= i && !expected &&
      (attr == 0 || attr == 1)){
    return !expected;
  }
  
  if(cmplog->headers[k].hits <= i) return expected;

  return kale_cmplog_is_true(cmplog, k, i, statement);
}

// Returns the index of a false cmplog given an entry in the cmplog, returns u32 max if none
u32 kale_get_false_entry(struct cmp_map* cmplog, u32 k){
    s64 fValue;
    for(u32 i = 0; i < cmplog->headers[k].hits <= i; i++){
      if(!kale_cmplog_is_true(cmplog, k, i, &fValue)){
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

  return CMP_MAP_W;
}

u8 kale_has_gradient(Angora* kale, unsigned size, int starting, int increment){
  for(int i = starting; i < size; i += increment){
    if(kale->gradients[i]) return 1;
  }
  return 0;
}

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size){
  return 1;
}

// http://locklessinc.com/articles/sat_arithmetic/
u8 sat_subu8(u8 x, u8 y)
{
	u8 res = x - y;
	res &= -(res <= x);
	
	return res;
}

s64 clamp(s64 d, s64 min, s64 max) {
  const s64 t = d < min ? min : d;
  return t > max ? max : t;
}

size_t afl_custom_fuzz(void* udata, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size){
  #ifdef DEBUG
  int total_execs = 0;
  int cmplog_missings = 0;
  #endif
  PRINT("Iteration...\n");
  int learningRate = 1;
  int modulationWidth = 5;
  const int modulationThreshold = 5000;
  const int EPSILON = 1;
  const int maxIterations = 50;
  const int annealingRate = 50;

  Angora* kale = (Angora*)udata;
  afl_state_t* afl = kale->afl;

  // Reset AFLs timeout
  u32 timeout_backup = afl->fsrv.exec_tmout;
  afl->fsrv.exec_tmout = UINT32_MAX;

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

  XXH64_reset(kale->hash_state, 3389);
  XXH64_update(kale->hash_state, buf, buf_size);
  XXH64_update(kale->hash_state, &i, sizeof(u32));
  XXH64_update(kale->hash_state, &k, sizeof(u32));
  XXH64_hash_t hash = XXH64_digest(kale->hash_state);
  size_t size = 0;
  unsigned char* map_stored_data;
  if((map_stored_data = kale_map_get(kale->map, hash, &size))){
    PRINT("Cache hit %lu\n", size);
    *out_buf = map_stored_data;    
    return size;
  }

  // backup stuff
  memcpy(&kale->cmp_backup, afl->shm.cmp_map, sizeof(struct cmp_map));

  afl_realloc((void**)&kale->out_buf, buf_size);
  *out_buf = kale->out_buf;
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

  s64 fValue;
  u8 initial_cmp_state = kale_cmplog_is_true(afl->shm.cmp_map, k, i, &fValue);
  unsigned int initial_attr = afl->shm.cmp_map->headers[k].attribute;

  int iterations = 0;  

  int bufIncrement;

  // Modulate the iteration
  // This is because when fuzzing a certain input most of the gradients are likely 0
  // We search only every modulationWidth gradients until we find a gradient
  if(buf_size > modulationThreshold){
    modulationWidth = modulationWidth * (buf_size / modulationThreshold);
    bufIncrement = modulationWidth;
  }else{
    bufIncrement = 1;
    modulationWidth = 1;
  }

  // The point where a gradient was found
  unsigned int save_point = 0;

  // Continually calculate gradient until it flips
  while(kale_cmplog_is_true_or_missing(afl->shm.cmp_map, k, i, &fValue, initial_attr, initial_cmp_state) == initial_cmp_state){
    if(abs(fValue) > 64) learningRate = 2;
    else learningRate = 1;

    // Calculate gradients of new input
    int starting = rand()%modulationWidth;

    s32 maxGradient = 0;

    for(int j = starting; j < buf_size; j += bufIncrement){
      s64 gradientBackup = 0;
      int epsilon = EPSILON;
      PRINT("%d/%lu                                             \r", j, buf_size);

      bool is_calculating_negative = false;
      if((*out_buf)[j] == 255) goto calcneg;
      goto go;

      // If we want we can jump here to try negative epsilon
      calcneg:
      if((*out_buf)[j] == 0) continue;
      epsilon = -EPSILON;
      is_calculating_negative = true;

      go:

      // we only ever use k, so we only need to clear k
      memset(afl->shm.cmp_map->headers+k, 0, sizeof(struct cmp_header));
      
      (*out_buf)[j] += epsilon;


      if (unlikely(common_fuzz_cmplog_stuff(afl, *out_buf, buf_size))) {
        // TODO: Error handling
        assert(false);
        return 0;
      }

      // Check if the if statement is no longer present, this could be because the args are equal
      // Or because the byte cant change
      if(afl->shm.cmp_map->headers[k].hits <= i){
        #ifdef DEBUG
        total_execs++;
        cmplog_missings++;
        #endif
        (*out_buf)[j] -= epsilon;

        // Try negative
        if(!is_calculating_negative) goto calcneg;
        continue;
      }

      kale->gradients[j] = kale_get_gradient(afl->orig_cmp_map, afl->shm.cmp_map, k, i, epsilon);

      if(!kale->gradients[j] && !is_calculating_negative) {
        (*out_buf)[j] -= epsilon;
        goto calcneg;
      }
      
      if(kale->gradients[j] && abs(kale->gradients[j]) > abs(maxGradient)){
        maxGradient = kale->gradients[j];
      }

      (*out_buf)[j] -= epsilon;

      if(kale->gradients[j] && bufIncrement > 1){
        // Go back and calculate for the previous
        j -= bufIncrement;
        save_point = j+1;
        bufIncrement = 1;
      }else if (j > save_point){ // Only reset to modulation if we are past the known hot-zone
        bufIncrement = modulationWidth;
      }

      #ifdef DEBUG
      total_execs++;
      #endif
    }

    // Make sure there is a gradient
    if(!maxGradient) {
      PRINT("NO GRADIENT\n");
      if(iterations > 1) goto success; // Even though we didn't flip the cmp, maybe its still interesting
      goto failure;
    }
    
    double scaleFactor = 1.0;
    if(maxGradient > 32){
      scaleFactor = 32 / (double)maxGradient;
      maxGradient = 32;
    }else if(maxGradient < -32){
      scaleFactor = -32 / (double)maxGradient;
      maxGradient = -32;
    }

    // Apply gradient descent
    descent:
    #ifdef DEBUG
    int gradient_total = 0;
    unsigned long input_total = 0;
    for (int ii = 0; ii < buf_size; ii++){
      input_total += (*out_buf)[ii];
    }

    for(int ii = starting; ii < buf_size; ii += bufIncrement){
      gradient_total += kale->gradients[ii];
    }

    printf("Applying gradient %d/%d, %d, %lu\n", cmplog_missings, total_execs, gradient_total, input_total);
    #endif

    for(int j = starting; j < buf_size; j += bufIncrement){
      char direction = initial_cmp_state*-1+(!initial_cmp_state);
      s64 normalizedGradient = kale->gradients[j] * scaleFactor;
      (*out_buf)[j] -= normalizedGradient * learningRate * direction;

      if(kale->gradients[j]){
        bufIncrement = 1;
      }else{
        bufIncrement = modulationWidth;
      }
    }

    // Do first cmplog pass
    memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);

    if (unlikely(common_fuzz_cmplog_stuff(afl, *out_buf, buf_size))) {
      // TODO: Error handling
      goto failure;
    }

    /*
    // if we lose the cmp map, lets just assume its the old cmpmap
    if(afl->shm.cmp_map->headers[k].hits <= i){
      iterations += 5;
      if (iterations == maxIterations) goto success;
     
      memcpy(afl->shm.cmp_map, afl->orig_cmp_map, sizeof(struct cmp_map));
      continue;
    }
    */

    // Save the original map
    memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));

    iterations++;
    // We did some stuff, so lets go to success, maybe its interesting
    if (iterations == maxIterations) goto success;

    /*if(annealingRate > 1 && iterations % annealingRate == 0){
        learningRate /= 2;
    }*/

  }

  // We are done, we have a new input that will evaluate to true
  success:
  // Restore original stuff
  memcpy(afl->shm.cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));
  memcpy(afl->orig_cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));

  kale_map_store(kale->map, hash, *out_buf, buf_size);
  afl->fsrv.exec_tmout = timeout_backup;

  #ifdef DEBUG
  unsigned long totalDiff = 0;
  for(int ii = 0; ii < buf_size; ii++){
    totalDiff += abs((*out_buf)[ii] - buf[ii]);
  }
  #endif

  PRINT("Iteration... Success %d, %lu\n\n", iterations, totalDiff);
  return buf_size;

  failure:
  memcpy(afl->shm.cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));
  memcpy(afl->orig_cmp_map, &kale->cmp_backup, sizeof(struct cmp_map));

  *out_buf = NULL;

  kale_map_store(kale->map, hash, NULL, 0);
  afl->fsrv.exec_tmout = timeout_backup;

  PRINT("Iteration... Failure %d\n\n", iterations);
  return 0;
}

void afl_custom_deinit(Angora* kale){
  kale_map_free(kale->map);
  XXH64_freeState(kale->hash_state);
  afl_free(kale->gradients);
  afl_free(kale->out_buf);

  free(kale);
}
