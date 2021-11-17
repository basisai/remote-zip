# remote-zip API documentation

## RemoteZipPointer

An uninitialised pointer to a remote ZIP file.

- `RemoteZipPointer({ url: URL, additionalHeaders?: Headers, method = "GET", credentials = "same-origin", headUrl?: URL } )`

- `RemoteZipPointer.populate(): Promise<RemoteZip>`

  Get an initialised `RemoteZip` object.

  - `headUrl` URL for HEAD request. Defaults to `url`. This can, for example, differ from `url` if you are using a signed URL for S3.

  Throws `RemoteZipError` if it fails to parse or fetch.

## RemoteZip

- `RemoteZip({ contentLength: number, url: URL, centralDirectoryRecords: CentralDirectoryRecord[], endOfCentralDirectory: EndOfCentralDirectory | null, credentials = "same-origin" })`

  Best construct this from a `RemoteZipPointer`.

  ```ts
  import { RemoteZipPointer } from "remote-zip";

  const url = new URL("http://www.example.com/test.zip");
  const remoteZip = await new RemoteZipPointer({ url }).populate();
  ```

- `RemoteZip.fetch(path: string, additionalHeaders?: Headers): Promise<ArrayBuffer>`

  Get the uncompressed file at `path` inside the remote ZIP file.

  ```ts
  import { RemoteZipPointer } from "remote-zip";

  const url = new URL("http://www.example.com/test.zip");
  const remoteZip = await new RemoteZipPointer({ url }).populate();
  const bytes = await remoteZip.fetch("test.txt"); // ArrayBuffer
  const text = new TextDecoder().decode(bytes); // Hello, world!
  ```

  Throws `RemoteZipError` if it fails to parse or fetch.

- `RemoteZip.files(): RemoteZipFile[]`

  Get the file listing of the remote ZIP file.

  ```ts
  import { RemoteZipPointer } from "remote-zip";

  const url = new URL("http://www.example.com/test.zip");
  const remoteZip = await new RemoteZipPointer({ url }).populate();
  const files = remoteZip.files();
  // files = [{ attributes: 1107099648, filename: "text.txt", modified: "2021-06-17T12:28:02", size: 14 }]
  ```

  Throws `RemoteZipError` if it fails to parse or fetch.
