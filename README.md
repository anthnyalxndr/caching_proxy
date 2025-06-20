# Caching Proxy

A TypeScript-based caching proxy server that allows you to view entire websites offline with or without an HTTPS connection. This proxy combines the power of a Man-in-the-Middle (MITM) proxy with intelligent caching capabilities to enable offline browsing of any content.

The caching proxy automatically caches websites based on your configuration, serves cached content when available, and periodically updates stale content to keep your offline resources fresh. This project was inspired by [devdocs.io/](https://devdocs.io) and aims to make it possible to view any documentation offline in its **native format** (i.e. the website it was originally hosted on).

For more information on the [Man-in-the-Middle proxy repository](https://github.com/anthnyalxndr/node_mitm_proxy) this project depends on.

## Features

- **Automatic Website Caching**: Cache entire websites including all subresources (CSS, JS, images, etc.)
- **Offline Browsing**: View cached websites without an internet connection
- **Intelligent Cache Management**: Automatic deletion of stale content and cleanup of removed sites
- **Configurable Update Frequencies**: Set how often each site should be refreshed
- **Hot Reloading**: Configuration changes are automatically detected and applied
- **HTTPS Support**: Full HTTPS interception and caching through MITM capabilities

## Prerequisites

The following sections define prerequisites for running the caching proxy. See the installation section for more details.

### System Requirements
- Node.js 16.x or higher
- OpenSSL installed on your system
- tsx (TypeScript execution engine)
- A valid root CA certificate and private key

### Proxy Configuration
Before using the caching proxy, you need to configure either your browser or system to use it. See the installation section for more information.

### Root Certificate Configuration
You must install and trust a root CA certificate on your local machine to be used by the proxy in order to successfully cache unencrypted HTTPS traffic.

**Note**: For detailed instructions on creating and configuring a root certificate, please refer to the [node_mitm_proxy repository](https://github.com/anthnyalxndr/node_mitm_proxy) documentation.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/anthnyalxndr/caching_proxy.git
    cd caching_proxy
    ```

2. Install npm dependencies:

    ```bash
    npm install
    ```

3. Clone the [node_mitm_proxy](https://github.com/anthnyalxndr/node_mitm_proxy) repository.

    ```bash
    # from within the caching_proxy directory.
    git clone https://github.com/anthnyalxndr/node_mitm_proxy.ts
    ```

4. Update the import for MitmProxy within caching_proxy.ts

    *caching_proxy.ts*
    ```ts
    import MitmProxy from "path/to/mitm_dir/mitm_proxy.ts";
    ```

5. Create, install, and trust a root CA certificate (if you haven't already). See the [node_mitm_proxy repository](https://github.com/anthnyalxndr/node_mitm_proxy) documentation for details.

6. Configure your system or browser to use the proxy:

    ⚠️ **Warning**:  It's highly recommended to use this caching proxy with Firefox because other browsers either...
    - Don't allow for browser specific proxy configuration or...
    - Don't respect system proxy settings when the host machine is offline. Viewing offline content with other browsers requires editing your `/etc/hosts` file and serving content from localhost:443 when offline.
  
   **Browser Configuration** :
     - **Firefox**:
       1. Open Settings
       2. Search for "proxy"
       3. Under "Network Settings", click "Settings"
       4. Select "Manual proxy configuration"
       5. Enter your proxy address and port
       6. Click "OK"

     - **Chrome/Edge**:
       1. Open Settings
       2. Search for "proxy"
       3. Click "Open your computer's proxy settings"
       4.  Under "Manual proxy setup", enable "Use a proxy server"
       5.  Enter your proxy address (e.g., `localhost`) and port (e.g., `3000`)
       6.  Click "Save"
   
   **System Configuration**:
     - **macOS**:
       ```bash
       # Set HTTP proxy
       networksetup -setwebproxy "Wi-Fi" localhost 3000
       # Set HTTPS proxy
       networksetup -setsecurewebproxy "Wi-Fi" localhost 3000
       # To disable the proxy
       networksetup -setwebproxystate "Wi-Fi" off
       networksetup -setsecurewebproxystate "Wi-Fi" off
       ```
     - **Linux**:
       ```bash
       # Set HTTP proxy
       export http_proxy=http://localhost:3000
       export HTTP_PROXY=http://localhost:3000
       # Set HTTPS proxy
       export https_proxy=http://localhost:3000
       export HTTPS_PROXY=http://localhost:3000
       # To disable the proxy
       unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
       ```
     - **Windows** (PowerShell):
       ```powershell
       # Set HTTP proxy
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value "localhost:3000"
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
       # To disable the proxy
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
       ```

## Usage

### Basic Usage

`example.ts`

```typescript
import CachingProxy from "./caching_proxy.ts";

const proxy = new CachingProxy({
    certCache: "./cert-cache",
    caCertPath: "./ca-cert.pem",
    caKeyPath: "./ca-key.pem",
    responseCache: "./response-cache"
});

// Start the proxy on port 3000
proxy.listen(3000, "localhost");
```

### Configuration

The caching proxy uses a `config.json` file to specify which websites to cache and how often to update them.

#### Configuration Format

```json
{
    "example.com": {
        "updateFrequency": 30
    },
    "docs.example.com": {
        "updateFrequency": 7
    },
    "api.example.com": {
        "updateFrequency": 1
    }
}
```

#### Configuration Options

- **`updateFrequency`**: Number of days between cache updates for each site
  - Lower values (1-7 days) for frequently changing content
  - Higher values (30+ days) for static documentation sites
  - Note: If you want to cache a few sites for offline use as a one-off, don't worry too much about the `updateFrequency` value chosen. When you don't need the cached content anymore just delete the sites from the `config.json` file.

#### Adding Sites to Cache

1. Edit the `config.json` file
2. Add the domain you want to cache (without `https://` or the url query)
   - E.g. `https://foo.com/bar?qux=fred#fragment` ---> `foo.com/bar#fragment`
3. Set the `updateFrequency` in days
4. Save the file - the proxy will automatically detect changes and cache the new sites

### Running the Proxy

Continuing with the `example.ts` file from above:

```bash
npx tsx example.ts
```

## How It Works

### Caching Process

1. **Initial Cache**: When you add a site to `config.json`, the proxy automatically:
   - Launches a headless browser (Playwright)
   - Navigates to the site
   - Scrolls through the entire page to trigger all resource loads
   - Caches all HTTP responses (HTML, CSS, JS, images, etc.)
   - Stores metadata about cached resources

2. **Serving Cached Content**: When you visit a cached site:
   - The proxy checks if a valid cached response exists
   - If found, serves the cached content immediately
   - If not found, tunnels the request to the origin server

3. **Cache Updates**: The proxy automatically:
   - Polls for expired cache entries daily
   - Re-caches sites that have exceeded their update frequency
   - Removes cached content for sites no longer in `config.json`

### Cache Storage

- **Response Cache**: Responses are stored in the `response-cache` directory (configurable)
- **Metadata**: Metadata is stored in `metadata.json` and is used for tracking relationships between sites and their subresources
- **Certificates**: Cached certificates are stored in the certificate cache directory for HTTPS sites

## Features in Detail

### Eager Caching

The proxy uses an eager caching strategy by leveraging Playwright to render and scroll each cached site upon proxy start up or configuration reload. Eager caching ensures all subresources are cached and the site is completely functional offline. Attempting to use a lazy caching approach can lead to missing subresources in the response cache when the user didn't fully scroll a page upon their initial visit.

### Intelligent Cache Management

- **Automatic Cleanup**: Removes cached resources when sites are removed from configuration
- **Stale Content Detection**: Automatically re-caches content based on update frequencies
- **Resource Relationships**: Tracks which subresources belong to which main sites

### Offline Support

Once cached, websites can be viewed completely offline over https. This is ideal in situations where you may be coding with limited connectivity, or if you want to reduce unecessary network usage on your machine or home network. Websites well suited to this purpose include:
- Documentation sites (MDN, TypeScript docs, etc.)
- Reference materials
- Frequently visited sites (that are mostly static) with limited connectivity

### Hot Configuration Reloading

Changes to `config.json` are automatically detected and applied without restarting the proxy.

## Configuration Reference

### CachingProxy Options

```typescript
interface Options {
    hostname?: string;         // Hostname to bind to (default: "localhost")
    port?: number;             // Port to listen on
    serverTimeout?: number;    // Server timeout in milliseconds
    certCache: string;         // Path to certificate cache directory
    caCertPath: string;        // Path to root CA certificate file
    caKeyPath: string;         // Path to CA private key file
    responseCache: string;     // Directory to store cached responses
}
```

### Cache Configuration

```typescript
interface ConfigValue {
    updateFrequency: number;    // Days between cache updates
}
```

## Troubleshooting

### Common Issues

1. **Certificate Errors**: Ensure the root CA certificate is properly installed and trusted
2. **Cache Not Updating**: Check that the site is properly configured in `config.json`
3. **Proxy Not Working**: Verify the proxy is running and your browser/system is configured correctly
4. **Memory Issues**: Large sites may require significant memory during initial caching


### Cache Management

- **Clear Cache**: Remove all entries from `config.json` and start the proxy to clear all cached content. Metadata will automatically be updated as well.


## Security Considerations

⚠️ **Important**: This caching proxy is intended for personal use. Using it in production or on untrusted networks could expose sensitive information.

- The proxy intercepts and decrypts HTTPS traffic
- Cached content is stored locally and may contain sensitive information
- Ensure proper access controls on the cache directory

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[ISC License](LICENSE)
