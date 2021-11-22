# remote-zip

[API documentation](https://basisai.github.io/remote-zip)

Fetch file listings and individual files from a remote ZIP file.

## Features

Without downloading the entire ZIP:

- Fetch individual files in a remote ZIP
- Fetch file listings

The gist of what the library does is:

1. Get the content size of the ZIP file using a HTTP HEAD request.
2. Get the last 100 bytes using HTTP Range queries (hoping it's enough) to read the end-of-central-directory (EOCD) section.
3. Using the EOCD, read the central directory (CD) section with a Range request. This section contains a complete file listing and file byte offsets in the ZIP.
4. To get individual files, use another Range request with an offset to get the local file header + compressed data.

## Limitations

- No ZIP64 support
- No encrypted ZIP support
- No stream support via `ReadableStream` due to testing/dev difficulties
- Long comments in a ZIP file might cause `populate()` to fail

## Install

```bash
yarn add @basisai/remote-zip
```

```bash
npm install --save @basisai/remote-zip
```

## Usage

See the [generated API documentation](https://basisai.github.io/remote-zip/).

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

<details>
<summary>Dev instructions</summary>
See `scripts` in `package.json` for more scripts.

- `yarn d` watch and build
- `yarn t:watch` watch and test
- `yarn lint`
- `yarn build`

Run tests and checks with Docker

```
docker-compose -f docker-compose.test.yml up --build
```

### Publish

#### Setup

1. Get an automation token from npm under settings

   ```
   https://www.npmjs.com/settings/aicadium/tokens/
   ```

2. Add the token to your repository secrets.

   ```
   https://github.com/$YOUR_USERNAME/$YOUR_REPO_NAME/settings/secrets/actions/new
   ```

   - Name: `NPM_TOKEN`
   - Value: The automation token you got from the previous step

#### Run

1. Create a new release.

   ```
   https://github.com/$YOUR_USERNAME/$YOUR_REPO_NAME/releases
   ```

   The workflow at `./github/workflows/publish.yml` should run and publish your packages to both NPM and GitHub Packages.

   Don't forget to bump your version number in `package.json` before this.
   </details>
