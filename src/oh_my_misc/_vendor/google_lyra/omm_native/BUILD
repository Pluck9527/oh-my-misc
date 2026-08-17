package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "libomm_lyra_native.so",
    srcs = ["lyra_c_api.cc"],
    linkshared = True,
    deps = [
        "//lyra/cli_example:decoder_main_lib",
        "//lyra/cli_example:encoder_main_lib",
        "@gulrak_filesystem//:filesystem",
    ],
)
