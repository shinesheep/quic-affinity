#include "quic_affinity/qaffinity.h"

#include <string.h>

int main(void) {
  return strcmp(qaff_stat_name(QAFF_STAT_PACKETS), "packets") == 0 ? 0 : 1;
}
