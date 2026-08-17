/*
 * C ABI wrapper for oh-my-misc.
 *
 * The wrapped codec implementation is Google's Lyra source tree vendored under
 * src/oh_my_misc/_vendor/google_lyra and licensed under Apache-2.0.
 */

#include <cstddef>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "include/ghc/filesystem.hpp"
#include "lyra/cli_example/decoder_main_lib.h"
#include "lyra/cli_example/encoder_main_lib.h"

namespace {

void CopyError(const std::string& message, char* error, std::size_t error_size) {
  if (error == nullptr || error_size == 0) {
    return;
  }
  const std::size_t n = message.size() < error_size - 1 ? message.size() : error_size - 1;
  std::memcpy(error, message.data(), n);
  error[n] = '\0';
}

bool IsEmptyPath(const char* value) { return value == nullptr || value[0] == '\0'; }

}  // namespace

extern "C" {

const char* omm_lyra_version() { return "google-lyra-1.3.2-capi"; }

int omm_lyra_encode_file(const char* wav_path, const char* output_path, int bitrate,
                         int enable_preprocessing, int enable_dtx, const char* model_path,
                         char* error, std::size_t error_size) {
  try {
    if (IsEmptyPath(wav_path)) {
      CopyError("wav_path is empty", error, error_size);
      return 2;
    }
    if (IsEmptyPath(output_path)) {
      CopyError("output_path is empty", error, error_size);
      return 2;
    }
    if (IsEmptyPath(model_path)) {
      CopyError("model_path is empty", error, error_size);
      return 2;
    }
    const std::string wav(wav_path);
    const std::string output(output_path);
    const std::string model(model_path);
    const bool ok = chromemedia::codec::EncodeFile(
        ghc::filesystem::path(wav), ghc::filesystem::path(output), bitrate,
        enable_preprocessing != 0, enable_dtx != 0, ghc::filesystem::path(model));
    if (!ok) {
      CopyError("Lyra EncodeFile returned false", error, error_size);
      return 1;
    }
    CopyError("", error, error_size);
    return 0;
  } catch (const std::exception& exc) {
    CopyError(exc.what(), error, error_size);
    return 3;
  } catch (...) {
    CopyError("unknown Lyra encode exception", error, error_size);
    return 4;
  }
}

int omm_lyra_decode_file(const char* encoded_path, const char* output_path, int sample_rate_hz,
                         int bitrate, int randomize_num_samples_requested,
                         float packet_loss_rate, float average_burst_length,
                         const float* fixed_starts, const float* fixed_durations,
                         std::size_t fixed_count, const char* model_path, char* error,
                         std::size_t error_size) {
  try {
    if (IsEmptyPath(encoded_path)) {
      CopyError("encoded_path is empty", error, error_size);
      return 2;
    }
    if (IsEmptyPath(output_path)) {
      CopyError("output_path is empty", error, error_size);
      return 2;
    }
    if (IsEmptyPath(model_path)) {
      CopyError("model_path is empty", error, error_size);
      return 2;
    }
    const std::string encoded(encoded_path);
    const std::string output(output_path);
    const std::string model(model_path);
    std::vector<float> starts;
    std::vector<float> durations;
    if (fixed_count > 0) {
      if (fixed_starts == nullptr || fixed_durations == nullptr) {
        CopyError("fixed packet-loss arrays are null", error, error_size);
        return 2;
      }
      starts.assign(fixed_starts, fixed_starts + fixed_count);
      durations.assign(fixed_durations, fixed_durations + fixed_count);
    }
    chromemedia::codec::PacketLossPattern pattern(starts, durations);
    const bool ok = chromemedia::codec::DecodeFile(
        ghc::filesystem::path(encoded), ghc::filesystem::path(output), sample_rate_hz, bitrate,
        randomize_num_samples_requested != 0, packet_loss_rate, average_burst_length, pattern,
        ghc::filesystem::path(model));
    if (!ok) {
      CopyError("Lyra DecodeFile returned false", error, error_size);
      return 1;
    }
    CopyError("", error, error_size);
    return 0;
  } catch (const std::exception& exc) {
    CopyError(exc.what(), error, error_size);
    return 3;
  } catch (...) {
    CopyError("unknown Lyra decode exception", error, error_size);
    return 4;
  }
}

}  // extern "C"
