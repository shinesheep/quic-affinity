#include "quic_affinity/quic_affinity.h"

#include <string.h>

int main(void) {
  return strcmp(qaff_stat_name(QAFF_STAT_PACKETS), "packets") == 0 ? 0 : 1;
}
