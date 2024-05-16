#include "witnesscalc_register_sha256WithRSAEncryption_65537.h"
#include "witnesscalc.h"

int
witnesscalc_register_sha256WithRSAEncryption_65537(
    const char *circuit_buffer,  unsigned long  circuit_size,
    const char *json_buffer,     unsigned long  json_size,
    char       *wtns_buffer,     unsigned long *wtns_size,
    char       *error_msg,       unsigned long  error_msg_maxsize)
{
    return CIRCUIT_NAME::witnesscalc(circuit_buffer, circuit_size,
                       json_buffer,   json_size,
                       wtns_buffer,   wtns_size,
                       error_msg,     error_msg_maxsize);
}