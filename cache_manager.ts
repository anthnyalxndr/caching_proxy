/* eslint-disable @typescript-eslint/non-nullable-type-assertion-style */
import http, { IncomingMessage } from "node:http";
import fs, { promises as fsp } from "node:fs";
import stream, { Readable } from "node:stream";
import playwright, { chromium } from "playwright";
import { promisify } from "node:util";
import zlib from "node:zlib";

/**
 * Represents a cached HTTP response with all necessary metadata
 */
export interface CachedResponse {
    /** Base64 encoded response body */
    body?: string;
    /** Array of header key-value pairs in [key, value, key, value, ...] format */
    headers: string[];
    /** HTTP status code */
    statusCode: number;
    /** HTTP status message */
    statusMessage: string;
    /** Optional buffer containing response body */
    buf?: Buffer;
    /** Configuration key associated with this cached response */
    configKey: string;
}

/**
 * Configuration options for initializing the CacheManager
 */
export interface Options {
    /** Hostname to bind the server to */
    hostname?: string;
    /** Port to listen on */
    port?: number;
    /** Timeout in milliseconds of inactivity to wait for server shutdown */
    serverTimeout?: number;
    /** Path to certificate cache directory to store TLS certificates */
    certDir: string;
    /** Path to root CA certificate file */
    caCertPath: string;
    /** Path to CA private key file */
    caKeyPath: string;
    /** Optional path to request log file */
    reqLogPath?: string;
    /** Directory to store cached responses */
    resCache: string;
}

/**
 * Extended HTTP server interface with additional properties
 */
export interface Server extends http.Server {
    /** Port number the server is listening on */
    port?: number;
    /** Hostname the server is bound to */
    hostname?: string;
    /** Optional page identifier */
    page?: string;
}

/**
 * Extended HTTP response type with request reference
 */
export type Response = http.ServerResponse & {
    /** Reference to the original request */
    req: http.IncomingMessage;
};

/**
 * Configuration value for a single site entry
 */
export interface ConfigValue {
    /** Update frequency in days */
    updateFrequency: number;
}

/**
 * Configuration mapping of site URLs to their update frequencies
 */
export type Config = Record<string, { updateFrequency: number }>;

/**
 * Type alias for hostname strings
 */
export type Hostname = string;

/**
 * Interface for node https secure context configuration
 */
export interface SecureContext {
    /** Private key buffer */
    key: Buffer;
    /** Certificate buffer */
    cert: Buffer;
}

/**
 * File format for metadata stored on disk
 */
interface ConfigMetadataFile {
    /** Metadata for configuration entries */
    configEntryMetadata: Record<
        string,
        {
            /** Timestamp of last update */
            lastUpdated: number;
            /** Array of subresource URLs */
            subresources: string[];
        }
    >;
    /** Metadata for subresources */
    subresourceMetadata: Record<string, { referencingEntries: string[] }>;
}

/**
 * In-memory metadata structure with Sets for efficient lookups
 */
interface ConfigMetadata {
    /** Metadata for configuration entries with Set for subresources */
    configEntryMetadata: Record<
        string,
        { lastUpdated: number; subresources: Set<string> }
    >;
    /** Metadata for subresources with Set for referencing entries */
    subresourceMetadata: Record<string, { referencingEntries: Set<string> }>;
}

/**
 * Manages caching of web resources and their metadata
 */
export default class CacheManager {
    /** Playwright browser instance used for fetching resources */
    browser: playwright.Browser | null = null;

    /** Base directory path for storing cached responses */
    resCache: string;

    /** Promise that resolves when initialization is complete */
    initPromise: Promise<ThisType<CacheManager>> | null = null;

    /** Set of URLs that have been cached. Used to prevent caching of duplicate responses.*/
    cachedUrls: Set<string>;

    /** Metadata about cached resources and their relationships */
    metadata: ConfigMetadata;

    /** Configuration for caching behavior */
    config: Config;

    /** Interval timer for periodically checking for expired cached responses. */
    pollInterval: NodeJS.Timeout | null = null;

    /** File system watcher for config.json changes */
    watcher: fs.StatWatcher | null = null;

    /** Timeout for debounced metadata writes */
    private writeTimeout: NodeJS.Timeout | null = null;

    /** Debounce timeout duration in milliseconds */
    private readonly writeTimeoutMs = 10000;

    /** Flag indicating if metadata needs to be written */
    private isDirty = false;

    /**
     * Creates a new CacheManager instance
     * @param resCache - Base directory path for storing cached responses
     */
    constructor(resCache: string) {
        this.resCache = resCache;
        this.cachedUrls = new Set();
        this.config = {};
        this.metadata = {
            configEntryMetadata: {},
            subresourceMetadata: {},
        };
    }

    /**
     * Initializes metadata from metadata.json file
     * @private
     */
    private async initializeMetadata() {
        try {
            const stat = await fsp.stat("./metadata.json");
            if (stat.size === 0) throw new Error("Metadata file is empty.");
        } catch (e) {
            await fsp.writeFile(
                "./metadata.json",
                JSON.stringify({
                    configEntryMetadata: {},
                    subresourceMetadata: {},
                })
            );
            return;
        }
        const file = await fsp.readFile("./metadata.json", {
            encoding: "utf8",
        });
        const json = JSON.parse(file) as ConfigMetadataFile;

        const { configEntryMetadata, subresourceMetadata } = this.metadata;

        for (const configKey in json.configEntryMetadata) {
            const entry = json.configEntryMetadata[configKey];
            const lastUpdated = entry?.lastUpdated ?? Date.now();
            const subresourceArr = entry?.subresources ?? [];
            configEntryMetadata[configKey] = {
                lastUpdated,
                subresources: new Set(subresourceArr),
            };
        }

        for (const subresource in json.subresourceMetadata) {
            const entry = json.subresourceMetadata[subresource];
            const referencingEntries = entry?.referencingEntries;
            if (!referencingEntries || referencingEntries.length === 0)
                continue;
            subresourceMetadata[subresource] = {
                referencingEntries: new Set(referencingEntries),
            };
        }
    }

    /**
     * Deletes empty parent directories up to the response cache root
     * @param filepath - Path to the file whose parent directories should be checked
     * @private
     */
    private async rmEmptyParentDirectories(filepath: string) {
        try {
            const dirArr = filepath.split("/").slice(0, -1);
            let curDir = dirArr.join("/");

            while ((await fsp.readdir(curDir)).length === 0) {
                if (curDir.split("/").at(-1) === "response-cache") break;
                await fsp.rmdir(curDir);
                dirArr.pop();
                curDir = dirArr.join("/");
            }
        } catch (err) {
            throw new Error("Unable to delete empty parent directories.", {
                cause: err,
            });
        }
    }

    /**
     * Deletes all resources associated with a config entry
     * @param key - Configuration key to delete resources for
     * @param removeMetadataEntry - Whether to remove the metadata entry
     * @private
     */
    private async deleteSiteResources(
        key: keyof ConfigMetadata,
        removeMetadataEntry = true
    ) {
        const { configEntryMetadata, subresourceMetadata } = this.metadata;
        const entry = configEntryMetadata[key];
        if (!entry) {
            throw new Error(
                `Failed to delete site resources.` +
                    `Config entry ${key} not found in metadata.`
            );
        }

        const subresources = entry.subresources;
        for (const s of subresources.values()) {
            const sMetadata = subresourceMetadata[s];
            if (!sMetadata) continue;
            sMetadata.referencingEntries.delete(key);
            if (sMetadata.referencingEntries.size === 0) {
                const { filepath } = this.getFileInfo(s);
                await fsp.rm(filepath);
                await this.rmEmptyParentDirectories(filepath);
                if (s in subresourceMetadata) delete subresourceMetadata[s];
                subresources.delete(s);
            }
        }

        const { filepath } = this.getFileInfo(key);
        await fsp.rm(filepath);
        await this.rmEmptyParentDirectories(filepath);
        if (removeMetadataEntry) delete configEntryMetadata[key];
        this.isDirty = true;
    }

    /**
     * Removes resources that are no longer in the config
     * @private
     */
    private async removeDeletedResources() {
        const { configEntryMetadata } = this.metadata;
        for (const confKey in configEntryMetadata) {
            if (confKey in this.config) continue;
            await this.deleteSiteResources(confKey as keyof ConfigMetadata);
        }
    }

    /**
     * Caches resources for config entries that are missing or expired
     * @param onlyCacheExpired - If true, only re-cache expired resources
     */
    async cacheMissingConfigEntries(onlyCacheExpired = false) {
        const { configEntryMetadata } = this.metadata;

        for (const key in this.config) {
            const configEntry = this.config[key]!;
            const updateFrequency = configEntry.updateFrequency;
            const metadataEntry = configEntryMetadata[key];
            const lastUpdated = metadataEntry?.lastUpdated;
            const msElapsed = lastUpdated
                ? Date.now() - lastUpdated
                : -Infinity;
            const daysElapsed = Math.trunc(msElapsed / (1000 * 60 * 60 * 24));
            const cachedResStale = daysElapsed >= updateFrequency;
            if (metadataEntry && !cachedResStale) continue;
            if (cachedResStale) {
                await this.deleteSiteResources(
                    key as keyof ConfigMetadata,
                    false
                );
                const metadataEntry = configEntryMetadata[key];
                if (metadataEntry) metadataEntry.lastUpdated = Date.now();
                await this.cacheSite(`https://${key}`);
                continue;
            }
            if (!onlyCacheExpired) await this.cacheSite(`https://${key}`);
        }
    }

    /**
     * Removes the query string from a URL
     * @param url - URL to remove query from
     * @returns URL without query parameters
     */
    removeQuery(url: string) {
        return url.includes("?") ? url.slice(0, url.indexOf("?")) : url;
    }

    /**
     * Removes a trailing forward slash from a string
     * @param str - String to remove trailing slash from
     * @returns String without trailing slash
     */
    removeTrailingSlash(str: string) {
        return str.endsWith("/") ? str.slice(0, -1) : str;
    }

    /**
     * Gets the filepath for a cached resource
     * @param pathArr - Array of path segments
     * @returns Full path to cached resource
     */
    getCachedResPath(pathArr: string[]) {
        const dirPath = [this.resCache, ...pathArr, ""].join("/");
        const filename = this.getFilename(pathArr);
        return dirPath + filename;
    }

    /**
     * Extracts filename for an array of path segments corresponding to a cached response.
     * @param pathArr - Array of path segments
     * @returns Filename with .json extension
     * @private
     */
    private getFilename(pathArr: string[]) {
        const filename = pathArr.at(-1);
        if (!filename)
            throw new Error(
                "Can't get filename information for empty path array."
            );
        return filename + ".json";
    }

    /**
     * Converts a flat array of headers to an object.
     * @param headers - Array of headers in [key, value, key, value, ...] format
     * @returns Object with header key-value pairs
     */
    toHeaderObj(headers: string[]): Record<string, string> {
        const entries: string[][] = [];
        if (headers.length === 0)
            throw new Error("Can't convert empty headers array to object.");
        if (headers.length % 2 !== 0)
            throw new Error(
                "Can't convert odd-length headers array to object."
            );
        for (let i = 0; i < headers.length; i += 2) {
            entries.push([headers[i], headers[i + 1]] as string[]);
        }
        return Object.fromEntries(entries) as Record<string, string>;
    }

    /**
     * Encodes response body based on accepted encodings
     * @param req - Incoming HTTP request
     * @param cachedRes - Cached response to encode
     * @private
     */
    private async encodeBody(
        req: http.IncomingMessage,
        cachedRes: CachedResponse
    ) {
        type CompressionFn =
            keyof typeof CacheManager.Dispatch.stream.compression;
        type DecompressionFn =
            keyof typeof CacheManager.Dispatch.stream.decompression;
        const { body, headers } = cachedRes;
        const headerObj = this.toHeaderObj(headers);
        if (!body) return;
        const { compression, decompression } = CacheManager.Dispatch.buffer;
        const acceptedEncodings = new Set(
            req.headers["accept-encoding"]?.split(", ")
        );
        const curEncoding = headerObj["content-encoding"] as DecompressionFn;
        if (acceptedEncodings.has(curEncoding)) return; // ...already encoded
        const decode = promisify(decompression[curEncoding]) as (
            buf: Buffer
        ) => Promise<Buffer>;
        const decoded = await decode(Buffer.from(body, "base64"));
        const compressionFns = new Set(Object.keys(compression));
        const encodingOverlap = [
            ...acceptedEncodings.intersection(compressionFns),
        ];
        const newEncoding = encodingOverlap[0];
        const encode = promisify(compression[newEncoding as CompressionFn]) as (
            buf: Buffer
        ) => Promise<Buffer>;
        const buf = await encode(decoded);
        const encoded = buf.toString("base64");
        if (newEncoding) headerObj["content-encoding"] = newEncoding;
        headerObj["content-length"] = String(buf.byteLength);
        cachedRes.body = encoded;
        cachedRes.headers = Object.entries(headerObj).flat();
    }

    /**
     * Modifies cached response based on request headers
     * @param req - Incoming HTTP request
     * @param cachedRes - Cached response to modify
     * @private
     */
    private async modifyRes(req: IncomingMessage, cachedRes: CachedResponse) {
        const headers = cachedRes.headers;
        const headersToSet = { date: new Date().toUTCString() };
        for (const name in headersToSet) {
            const idx = headers.indexOf(name);
            const val = headersToSet[name as keyof typeof headersToSet];
            if (idx === -1) headers.push(name, val);
            else headers[idx + 1] = val;
        }

        if (this.isConditionalReq(req.headers))
            this.createConditionalRes(cachedRes);
        else await this.encodeBody(req, cachedRes);
    }

    /**
     * Checks if request contains conditional headers
     * @param headers - Request headers to check
     * @returns True if request is conditional
     * @private
     */
    private isConditionalReq(headers: http.IncomingHttpHeaders) {
        const conditionalHeaders = new Set([
            "if-range",
            "if-unmodified-since",
            "if-modified-since",
            "if-none-match",
            "if-match",
        ]);
        const headerKeys = new Set(Object.keys(headers));
        return conditionalHeaders.intersection(headerKeys).size > 0;
    }

    /**
     * Creates a 304 Not Modified response from a cached 200 response.
     * @param cachedRes - Cached response to modify
     * @private
     */
    private createConditionalRes(cachedRes: CachedResponse) {
        const headers = cachedRes.headers;
        const contentHeaders = new Set([
            // Remove all content-* headers except content-type, csp, & content-location
            "content-base",
            "content-digest",
            "content-disposition",
            "content-encoding",
            "content-id",
            "content-language",
            "content-length",
            "content-md5",
            "content-range",
            "content-script-type",
            "content-security-policy-report-only",
            "content-security-policy",
            "content-style-type",
            "content-version",
        ]);

        for (let i = 0; i < headers.length; i += 2) {
            if (contentHeaders.has(headers[i] as string)) {
                headers.splice(i, 2);
                i -= 2;
            }
        }
        // Mutate cached res properties
        cachedRes.statusCode = 304;
        cachedRes.statusMessage = http.STATUS_CODES[304] as string;
        cachedRes.body = undefined;
    }

    /**
     * Serves a cached response from the file system. Potentially modifying it before sending it to the client.
     * @param req - Incoming HTTP request
     * @param res - HTTP response to write to
     */
    async serveCachedResponse(req: IncomingMessage, res: Response) {
        if (!req.headers.host || !req.url)
            throw new Error("Request headers are missing host or url.");
        const site = req.headers.host + req.url;
        const { filepath } = this.getFileInfo(site);
        const file: string = await fsp.readFile(filepath, {
            encoding: "utf-8",
        });
        const cachedRes = JSON.parse(file) as CachedResponse;
        // modify specific parts of request individually
        await this.modifyRes(req, cachedRes);
        const { headers, statusCode, statusMessage } = cachedRes;
        res.writeHead(statusCode, statusMessage, headers);
        if (cachedRes.body) {
            Readable.from(Buffer.from(cachedRes.body, "base64")).pipe(res);
        } else {
            res.end();
        }
    }

    /**
     * Removes scheme and query from URL
     * @param url - URL to normalize
     * @returns Normalized URL
     */
    removeSchemeAndQuery(url: string) {
        return this.removeScheme(this.removeQuery(url));
    }

    /**
     * Removes scheme from URL
     * @param url - URL to remove scheme from
     * @returns URL without scheme
     */
    removeScheme(url: string) {
        return url.replace(/http(s)?:\/\//, "");
    }

    /**
     * Checks if a URL has a valid cached response
     * @param url - URL to check
     * @returns True if valid cached response exists
     */
    async validCachedRes(url: string | undefined) {
        if (!url) return false;
        try {
            const { filepath } = this.getFileInfo(url);
            const stat = await fsp.stat(filepath); // throws on ENOENT
            return stat.size > 0;
        } catch (e) {
            if (e instanceof Error && "code" in e && e.code === "ENOENT")
                return false;
            throw e;
        }
    }

    /**
     * Compares two config objects or properties for equality
     * @param val1 - First object or property to compare
     * @param val2 - Second object or property to compare
     * @returns True if properties are equal
     */
    configUnchanged(val1: unknown, val2: unknown): boolean {
        type Asserter = (val: unknown) => val is object;
        const isObject: Asserter = (v) => typeof v === "object" && v !== null;
        if (val1 === val2) return true;
        if (isObject(val1) && isObject(val2)) {
            return (Object.keys(val1).length !== Object.keys(val2).length)
                ? false
                : Object.entries(val1)
                    .map(([k, v]) => {
                        return this.configUnchanged(
                            v,
                            (val2 as Record<string, unknown>)[k]
                        );
                    })
                    .every((el) => !!el);
        }
        return false;
    }

    /**
     * Initializes polling for updating expired cached responses.
     * @private
     */
    private initializePolling() {
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.pollInterval = setInterval(
            () => void this.cacheMissingConfigEntries(true),
            1000 * 60 * 60 * 24
        );
    }

    /**
     * Listener for config.json file watcher. Reloads config and updates metadata.
     * @private
     */
    private async onConfigChange() {
        const file = await fsp.readFile("./config.json", { encoding: "utf-8" });
        const newConfig = JSON.parse(file) as Config;
        if (this.configUnchanged(this.config, newConfig)) return;
        this.config = newConfig;
        await this.removeDeletedResources();
        await this.cacheMissingConfigEntries();
        this.initializePolling();
    }

    /**
     * Private method to initialize the cache manager and prevent memory-leaks caused by multiple initialization attempts.
     * @private
     */
    private async __init() {
        let promise, resolve, reject;
        try {
            if (this.initPromise) {
                return await this.initPromise; // ...already initializing
            } else {
                ({ promise, resolve, reject } = Promise.withResolvers());
                this.initPromise = promise as Promise<ThisType<CacheManager>>;
            }
            this.cachedUrls.clear();
            try {
                const file = await fsp.readFile("./config.json", {
                    encoding: "utf-8",
                });
                this.config = JSON.parse(file) as Config;
            } catch (e) {
                reject(
                    new Error("config.json is not valid JSON.", { cause: e })
                );
            }
            await this.initializeMetadata();
            await this.removeDeletedResources();
            this.scheduleMetadataWrite();
            this.browser = await chromium.launch();
            this.watcher ??= fs.watchFile(
                "./config.json",
                () => void this.onConfigChange()
            );
            resolve(this);
            return await promise;
        } catch (e) {
            await this.browser?.close();
            if (reject)
                reject(
                    new Error("Unable to initialize Cache Manager.", {
                        cause: e,
                    })
                );
            else throw e;
        }
    }

    /**
     * Public method to initialize the cache manager. Either calls #init or returns the existing initialization promise.
     * @returns Promise that resolves when initialization is complete
     */
    async init() {
        try {
            return await (
                this.initPromise ??= this.__init() as Promise<ThisType<CacheManager>>
            );
        } catch (e) {
            this.initPromise = null;
            throw new Error("Unable to initialize Cache Manager", { cause: e });
        }
    }

    /**
     * Gets file information for a cached resopnse associated with a URL.
     * @param url - URL to get file info for
     * @returns Object containing path, filename, and full filepath
     */
    getFileInfo(url: string) {
        const urlObj = new URL("https://" + url);
        const resource = (urlObj.hostname + urlObj.pathname).replace(/\/$/, "");
        const pathArr = resource.split("/");
        const filename = (pathArr.at(-1) as string) + ".json";
        const path = [this.resCache, ...pathArr, ""].join("/");
        const filepath = path + filename;
        return { path, filename, filepath };
    }

    /**
     * Sets the body of a cached response with proper encoding
     * @param res - Playwright response
     * @param data - Cached response data
     * @private
     */
    private async setBody(res: playwright.Response, data: CachedResponse) {
        const body = await res.body();
        const headerObj = this.toHeaderObj(data.headers);
        const compressionMap = CacheManager.Dispatch.buffer.compression;
        const encType = headerObj[
            "content-encoding"
        ] as keyof typeof compressionMap;
        const compress = promisify(compressionMap[encType]) as (
            body: Buffer
        ) => Promise<Buffer>;
        const buf = await compress(body);
        data.body = buf.toString("base64");
        headerObj["content-length"] = String(buf.byteLength);
        data.headers = Object.entries(headerObj).flat();
    }

    /**
     * Checks if an HTTP Response status code allows for a response body.
     * @param statusCode - HTTP status code
     * @returns True if status code allows body
     * @private
     */
    private statusHasBody(statusCode: number) {
        const codesWithoutBodies = new Set([204, 301, 302, 303, 307, 308]);
        return !codesWithoutBodies.has(statusCode);
    }

    /**
     * Checks if an HTTP request method expects a response with a body.
     * @param method - HTTP method
     * @returns True if a request with the given method expects a response with a body.
     * @private
     */
    private methodHasBody(method: string) {
        const methodWithoutBodies = new Set(["OPTIONS", "HEAD"]);
        return !methodWithoutBodies.has(method);
    }

    /**
     * Tests whether a response has a valid body.
     * @param res - Playwright response
     * @returns True if response has valid body
     * @private
     */
    private async validBody(res: playwright.Response) {
        try {
            const body = await res.body();
            const headers = res.headers();
            const contentLength = headers["content-length"] ?? String(body.length);
            const statusCode = res.status();
            const validStatus = this.statusHasBody(statusCode);
            const method = res.request().method();
            const validMethod = this.methodHasBody(method);
            const validContentLength = contentLength !== "0";
            return validStatus && validMethod && validContentLength;
        } catch (e) {
            return false;
        }
    }

    /**
     * Serializes cached response data
     * @param data - Cached response to serialize
     * @returns Serialized response data
     * @private
     */
    private serialize(data: CachedResponse) {
        return JSON.stringify(data);
    }

    /**
     * Formats response headers for use in http.ServerResponse.writeHead.
     * @param headers - Headers to format
     * @returns Formatted headers array
     * @private
     */
    private formatHeaders(headers: Record<string, string>): string[] {
        const delim = "\n";
        const entries = Object.entries(headers);
        const nested = entries.map(([k, v]) => {
            return !v.includes(delim)
                ? [k, v]
                : v.split(delim).map((v: string) => [k, v]);
        });
        return nested.flat(2);
    }

    /**
     * Gets the config.json key associated with a URL
     * @param url - URL to get config key for
     * @returns Config key
     * @private
     * @throws Error if no matching config key is found
     */
    private getConfigKey(url: string) {
        const normalized = this.normalizeUrl(url);
        const configKeys = new Set(Object.keys(this.config));
        if (configKeys.has(normalized)) return normalized;
        const wwwStripped = normalized.replace(/^www\./, "");
        if (configKeys.has(wwwStripped)) return wwwStripped;
        throw new Error("Cannot find matching config key.");
    }

    /**
     * Updates the metadata for a config entry and subresource and schedules a metadata write to disk.
     * @param configKey - Config key corresponding to a cached site.
     * @param subresourceUrl - URL corresponding to a cached subresource of the site associated with the config key.
     * @private
     */
    private updateConfigMetadata(configKey: string, subresourceUrl: string) {
        const normalized = this.normalizeUrl(subresourceUrl);
        const subresource = configKey === normalized ? null : normalized;
        const emptyMetadataEntry = {
            lastUpdated: Date.now(),
            subresources: new Set<string>(),
        };
        const emptySubresourceEntry = {referencingEntries: new Set<string>()};
        const { configEntryMetadata, subresourceMetadata } = this.metadata;
        const metadataEntry = 
            (configEntryMetadata[configKey] ??= emptyMetadataEntry);
        if (subresource) {
            const subresourceEntry = 
                (subresourceMetadata[subresource] ??= emptySubresourceEntry);
            metadataEntry.subresources.add(subresource);
            subresourceEntry.referencingEntries.add(configKey);
        }
        this.isDirty = true;
        this.scheduleMetadataWrite();
    }

    /**
     * Logs request information for debugging
     * @param res - Playwright response
     * @private
     */
    private logRequestInfo(res: playwright.Response) {
        console.error(
            "Caching Error: An error occurred while trying to cache a response."
        );
        console.error(
            `Response info:\n\tstatus: ${String(
                res.status()
            )}\n\tcontent-length: ` +
                `${res.headers()["content-length"] ?? "0"}\n\theaders: ` +
                JSON.stringify(res.headers(), null, 4)
        );
        console.error(
            `Request info:\n\turl: ${res.request().url()}\n\tmethod: ` +
                `${res.request().method()}\n\theaders: ` +
                JSON.stringify(res.request().headers(), null, 4)
        );
    }

    /**
     * Normalizes URL by removing scheme, query, and trailing slash. Used for looking up config keys.
     * @param url - URL to normalize
     * @returns Normalized URL
     * @private
     */
    private normalizeUrl(url: string) {
        const steps = [
            (s: string) => this.removeSchemeAndQuery(s),
            (s: string) => this.removeTrailingSlash(s),
        ];
        return steps.reduce((prev, cur) => cur(prev), url);
    }

    /**
     * Listener for requestfinished event. Caches all responses for requests generated by a page.
     * @param req - Playwright request
     * @private
     */
    private async cacheResponse(req: playwright.Request) {
        try {
            const resourceUrl = req.url();
            if (this.cachedUrls.has(resourceUrl)) return;
            const isDataUrl = (s: string) => /^data:.*?,.*/.test(s);
            const res = await req.response();
            if (!res || isDataUrl(resourceUrl)) return;
            this.cachedUrls.add(resourceUrl);
            const pageUrl = res.frame().url();
            const configLookup =
                pageUrl === "about:blank" ? resourceUrl : pageUrl;

            if (!configLookup)
                throw new Error("Can't get configKey (url) from res.");

            const configKey = this.getConfigKey(configLookup);

            const data: CachedResponse = {
                headers: this.formatHeaders(await res.allHeaders()),
                statusCode: res.status(),
                statusMessage: http.STATUS_CODES[res.status()] ?? "",
                configKey,
            };

            if (await this.validBody(res)) await this.setBody(res, data);
            const serialized = this.serialize(data);
            const fileInfo = this.getFileInfo(resourceUrl);
            await fsp.mkdir(fileInfo.path, { recursive: true, mode: 0o755 });
            await fsp.writeFile(fileInfo.filepath, serialized);
            this.updateConfigMetadata(configKey, resourceUrl);
        } catch (e) {
            console.error(e);
            const res = await req.response();
            if (res) this.logRequestInfo(res);
        }
    }

    /**
     * Schedule a write operation with debouncing
     * This prevents excessive disk writes when many updates happen quickly
     */
    private scheduleMetadataWrite(): void {
        // Clear any existing timeout to implement debouncing
        if (this.writeTimeout) clearTimeout(this.writeTimeout);
        this.writeTimeout = setTimeout(() => {
            // Queue the write operation to ensure it doesn't conflict with other operations
            void this.overwriteMetadata();
            this.writeTimeout = null;
        }, this.writeTimeoutMs);
    }

    /**
     * Changes shape of this.metadata to be serializable and then returns serialized metadata.
     * @returns Serialized metadata
     * @private
     */
    #createMetadataJson() {
        const { configEntryMetadata, subresourceMetadata } = this.metadata;
        const json: ConfigMetadataFile = {
            configEntryMetadata: {},
            subresourceMetadata: {},
        };

        for (const configKey in configEntryMetadata) {
            const entry = configEntryMetadata[configKey];
            const subresourceSet = entry?.subresources ?? new Set();
            const lastUpdated = entry?.lastUpdated ?? Date.now();
            const subresourceArr = [...subresourceSet];
            json.configEntryMetadata[configKey] = {
                lastUpdated,
                subresources: subresourceArr,
            };
        }

        for (const subresource in subresourceMetadata) {
            const entry = subresourceMetadata[subresource];
            const referencingEntries = entry?.referencingEntries ?? new Set();
            // TODO: Change below logic to match above for loop.
            const serializable =
                json.subresourceMetadata[subresource] ??
                (json.subresourceMetadata[subresource] = {
                    referencingEntries: [],
                });
            serializable.referencingEntries.push(...referencingEntries);
        }
        return JSON.stringify(json, null, 4);
    }

    /**
     * Writes metadata synchronously. Useful when gracefully shutting down the server.
     * @private
     */
    private writeMetadataSync() {
        if (!this.isDirty) return;
        const json = this.#createMetadataJson();
        const tmp = "./metadata.json.tmp";
        fs.writeFileSync(tmp, json);
        fs.renameSync(tmp, "./metadata.json");
        this.isDirty = false;
    }

    /**
     * Asynchronously writes the in-memory metadata to disk.
     * @private
     */
    private async overwriteMetadata() {
        if (!this.isDirty) return;
        const json = this.#createMetadataJson();
        const tmp = "./metadata.json.tmp";
        await fsp.writeFile(tmp, json);
        await fsp.rename(tmp, "./metadata.json");
        this.isDirty = false;
    }

    /**
     * Cleans up a Playwright page and its associated resources.
     * @param err - Error that caused the page to be cleaned up.
     * @param page - The page to clean up
     */
    async cleanupPage(err: unknown, page: playwright.Page | undefined) {
        if (err instanceof Error) console.error(err);
        if (!page) return;
        try {
            await page.removeAllListeners("requestfinished", {
                behavior: "wait",
            });
            if (!page.isClosed()) await page.close();
            await page.context().close();
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Force an immediate write of metadata (useful during shutdown)
     */
    public flushMetadata() {
        if (this.writeTimeout) {
            clearTimeout(this.writeTimeout);
            this.writeTimeout = null;
        }

        this.writeMetadataSync();
    }

    /**
     * Gracefully shuts down the cache manager.
     * @returns Promise that resolves when shutdown is complete
     */
    public async shutdown() {
        try {
            if (this.initPromise) await this.initPromise;
            this.flushMetadata();
            fs.unwatchFile("./config.json");
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
                this.pollInterval = null;
            }
            if (!this.browser) return;
            const promises: Promise<unknown>[] = [];
            const contexts = this.browser.contexts();
            contexts.forEach((c) => {
                const pages = c.pages();
                pages.forEach((p) => promises.push(this.cleanupPage(null, p)));
            });
            await Promise.allSettled(promises);
            await this.browser.close();
            this.initPromise = null;
            this.browser = null;
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Gradually scrolls to the end of a page to ensure all page subresources are cached.
     * @param page - The page to scroll
     * @private
     * @returns Promise that resolves when scrolling is complete
     */
    private async scrollPage(page: playwright.Page) {
        await page.evaluate(async () => {
            const { clientHeight } = window.document.documentElement;
            let i = clientHeight;
            while (i < document.body.scrollHeight) {
                window.scroll(0, i);
                await new Promise((resolve) => setTimeout(resolve, 100));
                i = window.scrollY + clientHeight;
            }
        });
    }

    /**
     * Caches a site by creating a new Playwright page, navigating to a url, scrolling to the bottom of the page, and caching responses each time the requestfinished event is triggered.
     * @param url - The URL of the site to cache
     * @returns Promise that resolves when caching is complete
     */
    public async cacheSite(url: string) {
        let page: playwright.Page | undefined;
        try {
            if (!this.initPromise) await this.init();
            if (!this.browser) throw new Error("Error initializing browser.");
            const context = await this.browser.newContext();
            page = await context.newPage();
            page.on("requestfinished", this.cacheResponse.bind(this));
            await page.goto(url, { waitUntil: "domcontentloaded" });
            await this.scrollPage(page);
            await page.waitForLoadState("networkidle");
            await this.cleanupPage(null, page);
        } catch (e) {
           void this.cleanupPage(e, page);
        }
    }

    /**
     * Dispatch table for compression and decompression functions.
     * @private
     */
    private static Dispatch = {
        stream: {
            compression: {
                br: zlib.createBrotliCompress,
                gzip: zlib.createGzip,
                deflate: zlib.createDeflate,
                zstd: zlib.createZstdCompress,
                undefined: () => new stream.PassThrough(),
            },
            decompression: {
                br: zlib.createBrotliDecompress,
                gzip: zlib.createGunzip,
                deflate: zlib.createInflate,
                zstd: zlib.createZstdDecompress,
                undefined: () => new stream.PassThrough(),
            },
        },
        buffer: {
            compression: {
                br: zlib.brotliCompress,
                gzip: zlib.gzip,
                deflate: zlib.deflate,
                zstd: zlib.zstdCompress,
                undefined: setImmediate,
            },
            decompression: {
                br: zlib.brotliDecompress,
                gzip: zlib.gunzip,
                deflate: zlib.inflate,
                zstd: zlib.zstdDecompress,
                undefined: setImmediate,
            },
        },
    };
}
