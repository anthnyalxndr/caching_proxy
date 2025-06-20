import CachingProxy from "./caching_proxy.ts";

// Ensure the following:
// 1. config.json file exists in the root directory.
// 2. caCertPath and caKeyPath are valid paths to the certificate and key files.
// 3. certCache is a valid path to the certificate cache directory.
// 4. responseCache is a valid path to the response cache directory.
const proxy = new CachingProxy({
    certCache: "/Users/foo/cert-cache",
    caCertPath: "/Users/foo/ca/cacert.pem",
    caKeyPath: "/Users/foo/ca/cakey.pem",
    openSSLConfigPath: "/Users/foo/ca/openssl.cnf",
    responseCache: "./response-cache"
});

proxy.listen(3000, "localhost");
