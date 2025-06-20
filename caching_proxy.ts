import { EventEmitter } from "events"; EventEmitter.captureRejections = true;
import http from "node:http";
import events from "node:events";
import CacheManager from "./cache_manager.ts";
import MitmProxy from "../node_mitm_proxy/mitm_proxy.ts";

/**
 * Configuration interface for caching proxy settings
 * Maps configuration keys to their update frequency settings
 */
export type Config = Record<string, {
        updateFrequency: number;
    }>;

/**
 * Represents a cached HTTP response and its metadata
 */
export interface CachedResponse {
    /** Response body as a base64 encoded string if available */
    body?: string
    /** A flat array of response headers */
    headers: string[];
    /** HTTP status code */
    statusCode: number;
    /** HTTP status message */
    statusMessage: string;
    /** Key used to identify this response in the cache */
    configKey: string;
}

/**
 * Configuration options for initializing the CachingProxy
 */
export interface Options {
    /** Timeout in milliseconds of inactivity to wait for server shutdown */
    serverTimeout?: number;
    /** Path to certificate cache directory to store TLS certificates */
    certCache: string;
    /** Path to root CA certificate file */
    caCertPath: string;
    /** Path to CA private key file */
    caKeyPath: string;
    /** Path to OpenSSL configuration file */
    openSSLConfigPath: string;
    /** Directory to store cached responses */
    responseCache: string;
}

/**
 * Extended HTTP server interface with additional properties
 */
export interface Server extends http.Server {
    /** Port number the server is listening on */
    port?: number;
    /** Hostname the server is bound to */
    hostname?: string;
    /** Promise resolving when server is listening */
    listeningPromise?: PromiseWithResolvers<null>;
}

/**
 * Extended HTTP response type with request reference
 */
export type Response = http.ServerResponse & {
    /** Reference to the original request */
    req: http.IncomingMessage;
}

/**
 * Extended HTTP incoming message type for proxy responses
 */
export type ProxyResponse = http.IncomingMessage & { 
    /** Reference to the client request if available */
    req?: http.ClientRequest; 
}

/**
 * Configuration entry interface specifying update frequency
 */
export interface ConfigValue {
    /** Frequency in milliseconds at which to update cached content */
    "updateFrequency": number
};

/** Type alias for config.json key strings */
export type ConfigKey = string;

/** Type alias for hostname strings */
export type Hostname = string;

/** Type alias for port numbers */
export type Port = number;

/**
 * Interface for node https secure context configuration
 */
export interface SecureContext {
    /** Private key buffer */
    key: Buffer, 
    /** Certificate buffer */
    cert: Buffer
};

/**
 * Main caching proxy class that handles HTTP/HTTPS proxying with response caching
 */
export default class CachingProxy extends events.EventEmitter {

    /** Cache manager instance for handling response caching */
    cacheManager: CacheManager;
    /** Hostname the proxy is bound to */
    hostname: string | undefined;
    /** MITM proxy instance */
    mitmProxy: MitmProxy;
    /** Port the proxy is listening on */
    port: number | null = null;
    /** Directory for storing cached responses */
    responseCache: string;
    /** Promise resolving when shutdown is complete */
    shutdownPromise: Promise<void> | null = null;
    /** Default timeout for requests in milliseconds */
    static RequestTimeout = 3000;

    /**
     * Creates a new CachingProxy instance
     * @param options - Configuration options for the proxy
     */
    constructor(options: Options) {
        super();
        this.responseCache = options.responseCache;
        this.mitmProxy = new MitmProxy({
            ...options, 
            requestHandler: this.onRequest.bind(this), 
        });
        this.cacheManager = new CacheManager(this.responseCache);
        this.#bindListeners();
        void this.cacheManager.init().then(() => {
            void this.cacheManager.cacheMissingConfigEntries();
        });
    }

    /**
     * Initiates the shutdown process for the proxy
     * @returns Promise that resolves when shutdown is complete
     */
    async shutdown() {
        await (this.shutdownPromise ??= this.#shutdown());
    }

    /**
     * Binds event listeners for process signals to ensure graceful shutdown.
     * @private
     */
    #bindListeners() {
        process.on("SIGINT", () => {
            this.shutdown().catch(() => {
                console.error("Unable to shutdown proxy successfully on SIGINT.");
                process.exit(1);
            });
        });
        process.on("SIGTERM", () => {
            this.shutdown().catch(() => {
                console.error("Unable to shutdown proxy successfully on SIGTERM.");
                process.exit(1);
            });
        });
    }

    /**
     * Performs the main shutdown sequence
     * @private
     */
    async #shutdown() {
        let promise, resolve, reject;
        try {
            if (this.shutdownPromise) {
                await this.shutdownPromise;
                return;
            } 
            ({promise, resolve, reject} = Promise.withResolvers<void>());
            this.shutdownPromise = promise;
            this.mitmProxy.shutdown();
            await this.cacheManager.shutdown();
            this.mitmProxy.httpServer.unref();
            resolve();
            await promise;
        } catch (e) {
            if (reject) reject(e);
            return promise;
        }
    }

    /**
     * Starts the proxy server listening on specified port and hostname
     * @param port - Port number to listen on
     * @param hostname - Hostname to bind to
     * @param cb - Optional callback function
     */
    listen(port: number, hostname: string, cb?: () => void) {
        if (this.mitmProxy.httpServer.listening) 
            throw new Error("server already listening");
        this.mitmProxy.listen(port, hostname, cb);
    }


    /**
     * Handles incoming HTTP requests
     * @param req - HTTP request object
     * @param res - HTTP response object
     * @param next - Optional next function to call if request should be passed to the next handler
     * @private
     */
    onRequest(req: http.IncomingMessage, res: Response, next?: () => void) {
        try {
            const {hostname} = this.#splitHost(req.headers.host);
            if (!req.url) throw new Error("Request URL is undefined");
            this.cacheManager.validCachedRes(hostname + req.url)
                .then(valid => {
                    if (valid) {
                        this.cacheManager.serveCachedResponse(req, res)
                            .catch((err: unknown) => {
                                console.error("An error occured while trying to serve a cached response.");
                                console.error(err);
                                next?.();
                            });
                    } else {
                        next?.();
                    }
                })
                .catch((err: unknown) => {
                    console.error("An error occured while trying to serve a cached response.");
                    console.error(err);
                    next?.();
                });
        } catch (e) {
            console.error(e);
            next?.();
        }
    }
    
    /**
     * Splits request URL into hostname and port
     * @param reqUrl - Request URL string
     * @returns Object containing hostname and port
     * @private
     */
    #splitHost(reqUrl: string | undefined): {hostname: string; port: number} {
        if (!reqUrl) throw new Error("Request URL is undefined");
        const parts = reqUrl.split(":", 2);
        const [hostname, port] = parts;
        if (!hostname) 
            throw new Error(`Host header missing from request for ${reqUrl}`);
        const portNum = port ? parseInt(port, 10) : 443;
        return { hostname, port: portNum };
    };
}