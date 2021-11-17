import { RemoteZipPointer } from "./zip";

import * as hs from "http-server";
import { Server } from "http";

describe("RemoteZip integration tests", () => {
  let server: Server;
  const url = new URL("http://127.0.0.1:9875/test.zip");

  beforeAll(() => {
    server = hs.createServer({
      root: "fixtures",
    });
    server.listen(9875, "127.0.0.1");
  });

  afterAll(() => {
    server.close();
  });

  describe("RemoteZip", () => {
    it("fetches and decompresses remote file in zip", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      const decoder = new TextDecoder();
      const bytes = await remoteZip.fetch("test.txt");
      expect(decoder.decode(bytes)).toBe("Hello, world!\n");
    });

    it("errors when fetching a missing file", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("bad")).rejects.toThrow(
        "File not found in remote ZIP: bad"
      );
    });

    it("supports alternative HTTP methods", async () => {
      await expect(
        new RemoteZipPointer({
          url,
          additionalHeaders: undefined,
          method: "POST",
        }).populate()
      ).rejects.toThrow(
        "Could not fetch remote ZIP at http://127.0.0.1:9875/test.zip: HTTP status 405"
      );
    });

    it("provides a friendly listing of files in the zip", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      const files = remoteZip.files();

      expect(files).toHaveLength(4);
      expect(files[0]).toEqual({
        filename: "dir/",
        modified: "2021-11-10T12:37:26",
        size: 0,
        attributes: 1107099648,
      });
      expect(files[1]).toEqual({
        filename: "xir/testdir.txt",
        modified: "2021-06-17T12:28:02",
        size: 14,
        attributes: 2176057344,
      });
    });
  });

  describe("RemoteZipPointer", () => {
    it("fetches and parses end of central directory record", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      expect(remoteZip.contentLength).toBe(863);
      expect(
        remoteZip.endOfCentralDirectory?.data.centralDirectoryByteOffset
      ).toBe(488);
    });

    it("fetches and parses central directory records", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      expect(remoteZip.centralDirectoryRecords?.length).toBe(4);
      expect(remoteZip.centralDirectoryRecords[0].data.filename).toBe("dir/");
      expect(remoteZip.centralDirectoryRecords[1].data.filename).toBe(
        "xir/testdir.txt"
      );
      expect(remoteZip.centralDirectoryRecords[2].data.filename).toBe(
        "test.txt"
      );
      expect(remoteZip.centralDirectoryRecords[3].data.filename).toBe(
        "test-inner.zip"
      );
    });
  });
});
