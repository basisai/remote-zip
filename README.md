# remote-zip

- [API](docs/api.md)

---

Without downloading the entire ZIP file:

- Fetch individual files from a remote ZIP
- Fetch file listings from a remote ZIP

The gist of what the library does is:

1. Get the content size of the ZIP file using a HTTP HEAD request.
2. Get the last 100 bytes using HTTP Range queries (hoping it's enough) to read the end-of-central-directory (EOCD) section.
3. Using the EOCD, read the central directory (CD) section with a Range request. This section contains a complete file listing and file byte offsets in the ZIP.
4. To get individual files, use another Range request with an offset to get the local file header + compressed data.

## Features

Without downloading the entire ZIP:

- Fetch individual files in a remote ZIP
- Fetch file listings
- Supports additional headers for fetch calls (auth, etc).

## Limitations

- No ZIP64 support
- No encrypted ZIP support
- No stream support via `ReadableStream` due to testing/dev difficulties
- Long comments in a ZIP file might cause `populate()` to fail

## Install

```
yarn add $TODO
```

## Usage

See [docs/api.md](docs/api.md) for API documentation.

If using in the browser, the server will need to whitelist CORS for `GET`, `HEAD`, and the `Range` header.

### Basic

```ts
const url = new URL("http://www.example.com/test.zip");
const remoteZip = await new RemoteZipPointer({ url }).populate();
const fileListing = remoteZip.files(); // RemoteZipFile[]
const uncompressedBytes = await remoteZip.fetch("test.txt"); // ArrayBuffer
```

### With more features

```ts
const method = "POST";
const additonalHeaders = new Headers();
additonalHeaders.append("X-Example", "foobar");
const url = new URL("http://www.example.com/test.zip");
const remoteZip = await new RemoteZipPointer({
  url,
  additionalHeaders,
  method,
  credentials: "include",
}).populate();
const uncompressedBytes = await remoteZip.fetch("test.txt", additionalHeaders);
```

## Dev

See `scripts` in `package.json` for more scripts.

- `yarn d` watch and build
- `yarn t:watch` watch and test
- `yarn lint`
- `yarn build`

Run tests and checks with Docker

```
docker-compose -f docker-compose.test.yml up --build
```
