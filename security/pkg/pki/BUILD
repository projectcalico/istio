load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "claims.go",
        "crypto.go",
        "san.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_golang_glog//:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "claims_test.go",
        "crypto_test.go",
        "san_test.go",
    ],
    library = ":go_default_library",
)
